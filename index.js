import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import crypto from "node:crypto";
import Stripe from "stripe";

const app = express();
const port = process.env.PORT || 5000;

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
  }),
);

app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);

app.use((req, res, next) => {
  console.log(`[server] ${req.method} ${req.originalUrl}`);
  next();
});

const client = new MongoClient(
  `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASS}@cluster0.cejh16o.mongodb.net/`,
);
const DB_NAME = "wedplan";

async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB");
    return client;
  } catch (err) {
    console.error("MongoDB Connection Failed:", err);
    throw err;
  }
}

let db;
let server;

const connectedClient = await connectToMongoDB();
db = connectedClient.db(DB_NAME);
const users = db.collection("user");
const services = db.collection("services");
const bookings = db.collection("bookings");
const transactions = db.collection("transactions");
const serviceCatalog = db.collection("serviceCatalog");

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const JWT_JWKS_URL =
  process.env.JWKS_URL || "http://localhost:3000/api/auth/jwks";

async function verifyJwt(token) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("Malformed token");
  const [header, payload, signature] = parts;
  const decodedHeader = JSON.parse(
    Buffer.from(header, "base64url").toString("utf8"),
  );
  const keysRes = await fetch(JWT_JWKS_URL);
  if (!keysRes.ok)
    throw new Error(`Failed to fetch JWKS (HTTP ${keysRes.status})`);
  const jwk = (await keysRes.json()).keys?.find(
    (k) => k.kid === decodedHeader.kid,
  );
  if (!jwk) throw new Error("No matching key in JWKS");
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const valid = crypto.verify(
    null,
    Buffer.from(`${header}.${payload}`),
    key,
    Buffer.from(signature, "base64url"),
  );
  if (!valid) throw new Error("Invalid token signature");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000))
    throw new Error("Token expired");
  const userId = claims.sub || claims.userId || claims.id;
  if (!userId) throw new Error("Token is missing the subject");
  return { userId: String(userId) };
}

const CATEGORIES = [
  "Photography & Videography",
  "Wedding Venues",
  "Decoration & Florist",
  "Catering Services",
  "Makeup & Styling",
  "Wedding Fashion",
];

const escapeRegex = (value) =>
  String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const findUser = (id) => db.collection("user").findOne(userQuery(String(id)));
const countUsers = (filter = {}) =>
  db.collection("user").countDocuments(filter);
const findService = (id) =>
  ObjectId.isValid(id)
    ? db.collection("services").findOne({ _id: new ObjectId(id) })
    : null;

const resolveServiceSort = (sort) => {
  if (sort && typeof sort === "object") return sort;
  const s = String(sort || "").toLowerCase();
  if (s === "price:asc") return { price: 1 };
  if (s === "price:desc") return { price: -1 };
  if (s === "createdat:asc") return { createdAt: 1 };
  return { createdAt: -1 };
};

const findServicesFiltered = async ({
  approvedOnly = false,
  query,
  category,
  location,
  status,
  sort,
  skip = 0,
  limit = 12,
}) => {
  const filter = {};
  if (approvedOnly) filter.status = "approved";
  if (status) filter.status = status;
  if (category) filter.category = category;
  if (location) filter.location = location;
  if (query) {
    const esc = escapeRegex(String(query));
    filter.$or = [
      { serviceName: new RegExp(esc, "i") },
      { description: new RegExp(esc, "i") },
    ];
  }
  const sortSpec = resolveServiceSort(sort);
  const [items, total] = await Promise.all([
    db
      .collection("services")
      .find(filter)
      .sort(sortSpec)
      .skip(skip)
      .limit(limit)
      .toArray(),
    db.collection("services").countDocuments(filter),
  ]);
  return { items: items.map(serializeService), total };
};

const serializeCatalogEntry = (e) => e && { ...e, id: String(e._id) };

const serializeService = (s) => s && { ...s, id: String(s._id) };

const serializeBooking = (b) => b && { ...b, id: String(b._id ?? b.id) };

const verifyStripeSignature = (rawBody, signatureHeader) => {
  const parts = String(signatureHeader || "")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  const timestampPart = parts.find((p) => p.startsWith("t="));
  const signaturePart = parts.find((p) => p.startsWith("v1="));
  if (!timestampPart || !signaturePart) return false;
  const timestamp = Number(timestampPart.slice(2));
  if (
    !Number.isFinite(timestamp) ||
    Math.abs(Date.now() / 1000 - timestamp) > 300
  )
    return false;
  const expected = crypto
    .createHmac("sha256", process.env.STRIPE_SECRET_KEY)
    .update(rawBody)
    .digest("hex");
  const provided = signaturePart.slice(3);
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(provided, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const userQuery = (id) => {
  const clauses = [{ _id: id }, { id }];
  if (ObjectId.isValid(id)) clauses.push({ _id: new ObjectId(id) });
  return { $or: clauses };
};

const STRIPE_PREMIUM_CURRENCY = "USD";
const STRIPE_PREMIUM_AMOUNT = 1200;
const STRIPE_PREMIUM_15_AMOUNT = 600;
const PREMIUM_DURATION_DAYS = 15;
const PLAN_15_DURATION_DAYS = 15;

const stripeConfig = {
  secretKey: process.env.STRIPE_SECRET_KEY,
  premiumAmount: STRIPE_PREMIUM_AMOUNT,
  premiumCurrency: STRIPE_PREMIUM_CURRENCY,
  premiumDurationDays: PREMIUM_DURATION_DAYS,
  premium15Amount: STRIPE_PREMIUM_15_AMOUNT,
  premium15DurationDays: PLAN_15_DURATION_DAYS,
  priceId: null,
};

const isPremiumUser = (u) =>
  u?.subscriptionPlan === "premium" && (!u.subscriptionExpiresAt || new Date(u.subscriptionExpiresAt) > new Date());

async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match)
      return res
        .status(401)
        .json({ success: false, message: "Missing Authorization header" });
    const { userId } = await verifyJwt(match[1]);
    const user = await findUser(userId);
    if (!user)
      return res
        .status(401)
        .json({ success: false, message: "Account not found" });
    if (user.isBlocked)
      return res
        .status(403)
        .json({ success: false, message: "Your account has been blocked. Contact support." });
    req.user = {
      id: String(user._id ?? user.id),
      name: user.name,
      email: user.email,
      image: user.image ?? null,
      role: user.role ?? "customer",
      isBlocked: Boolean(user.isBlocked),
      businessName: user.businessName ?? null,
      subscriptionPlan: user.subscriptionPlan ?? "free",
      subscriptionExpiresAt: user.subscriptionExpiresAt ?? null,
      createdAt: user.createdAt ?? null,
    };
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: err.message });
  }
};

const requireRole =
  (...roles) =>
  (req, res, next) => {
    if (!req.user)
      return res
        .status(401)
        .json({ success: false, message: "Authentication required" });
    if (!roles.includes(req.user.role))
      return res.status(403).json({ success: false, message: "Forbidden" });
    next();
  };

app.get("/api/services/meta", (req, res) => {
      res.json({
        success: true,
        data: {
          categories: CATEGORIES,
        },
      });
    });

    app.get(
      "/api/services/catalog",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const page = Math.max(1, Number.parseInt(req.query.page) || 1);
        const limit = Math.min(
          50,
          Math.max(1, Number.parseInt(req.query.limit) || 25),
        );
        const skip = (page - 1) * limit;
        const filter = {};
        if (req.query.q)
          filter.serviceName = new RegExp(
            escapeRegex(String(req.query.q)),
            "i",
          );
        const [items, total] = await Promise.all([
          serviceCatalog
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
          serviceCatalog.countDocuments(filter),
        ]);
        res.json({
          success: true,
          data: {
            entries: items.map(serializeCatalogEntry),
            meta: {
              page,
              limit,
              total,
              totalPages: Math.max(1, Math.ceil(total / limit)),
            },
          },
        });
      },
    );

    app.get(
      "/api/services/catalog/:id",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const entry = ObjectId.isValid(req.params.id)
          ? await serviceCatalog.findOne({ _id: new ObjectId(req.params.id) })
          : null;
        if (!entry)
          return res
            .status(404)
            .json({ success: false, message: "Catalog entry not found" });
        res.json({
          success: true,
          data: { entry: serializeCatalogEntry(entry) },
        });
      },
    );

    app.post(
      "/api/services/catalog",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const body = req.body ?? {};
        if (
          !body.serviceName ||
          !body.category ||
          !body.description ||
          body.price === undefined ||
          !body.location
        ) {
          return res
            .status(400)
            .json({ success: false, message: "Missing required fields" });
        }
        if (!CATEGORIES.includes(body.category)) {
          return res
            .status(400)
            .json({ success: false, message: "Invalid category" });
        }
        const numericPrice = Number(body.price);
        if (!Number.isFinite(numericPrice) || numericPrice < 0) {
          return res
            .status(400)
            .json({
              success: false,
              message: "price must be a non-negative number",
            });
        }
        const images = Array.isArray(body.images)
          ? body.images.filter((u) => typeof u === "string" && u.trim())
          : [];
        const now = new Date();
        const { insertedId } = await serviceCatalog.insertOne({
          serviceName: String(body.serviceName).trim(),
          category: body.category,
          description: String(body.description).trim(),
          price: numericPrice,
          location: String(body.location).trim(),
          images,
          createdAt: now,
          updatedAt: now,
        });
        const entry = await serviceCatalog.findOne({ _id: insertedId });
        res
          .status(201)
          .json({
            success: true,
            data: { entry: serializeCatalogEntry(entry) },
            message: "Catalog entry created",
          });
      },
    );

    app.patch(
      "/api/services/catalog/:id",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const entry = ObjectId.isValid(req.params.id)
          ? await serviceCatalog.findOne({ _id: new ObjectId(req.params.id) })
          : null;
        if (!entry)
          return res
            .status(404)
            .json({ success: false, message: "Catalog entry not found" });
        const patch = {};
        if (req.body.serviceName !== undefined)
          patch.serviceName = String(req.body.serviceName).trim();
        if (req.body.description !== undefined)
          patch.description = String(req.body.description).trim();
        if (req.body.location !== undefined)
          patch.location = String(req.body.location).trim();
        if (req.body.category !== undefined) {
          if (!CATEGORIES.includes(req.body.category))
            return res
              .status(400)
              .json({ success: false, message: "Invalid category" });
          patch.category = req.body.category;
        }
        if (req.body.price !== undefined) {
          const numericPrice = Number(req.body.price);
          if (!Number.isFinite(numericPrice) || numericPrice < 0) {
            return res
              .status(400)
              .json({
                success: false,
                message: "price must be a non-negative number",
              });
          }
          patch.price = numericPrice;
        }
        if (req.body.images !== undefined) {
          if (!Array.isArray(req.body.images))
            return res
              .status(400)
              .json({ success: false, message: "images must be an array" });
          patch.images = req.body.images.filter(
            (u) => typeof u === "string" && u.trim(),
          );
        }
        if (Object.keys(patch).length > 0) {
          await serviceCatalog.updateOne(
            { _id: entry._id },
            { $set: { ...patch, updatedAt: new Date() } },
          );
        }
        res.json({
          success: true,
          data: {
            entry: serializeCatalogEntry(
              await serviceCatalog.findOne({ _id: entry._id }),
            ),
          },
          message: "Catalog entry updated",
        });
      },
    );

    app.delete(
      "/api/services/catalog/:id",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const entry = ObjectId.isValid(req.params.id)
          ? await serviceCatalog.findOne({ _id: new ObjectId(req.params.id) })
          : null;
        if (!entry)
          return res
            .status(404)
            .json({ success: false, message: "Catalog entry not found" });
        await serviceCatalog.deleteOne({ _id: entry._id });
        res.json({ success: true, message: "Catalog entry deleted" });
      },
    );

    app.get("/api/services", async (req, res) => {
      const page = Math.max(1, Number.parseInt(req.query.page) || 1);
      const limit = Math.min(
        50,
        Math.max(1, Number.parseInt(req.query.limit) || 12),
      );
      const skip = (page - 1) * limit;
      const filter = { status: "approved", isActive: true };
      if (req.query.category) filter.category = req.query.category;
      if (req.query.location) filter.location = req.query.location;
      if (req.query.status) filter.status = req.query.status;
      if (req.query.q) {
        const esc = escapeRegex(String(req.query.q));
        filter.$or = [
          { serviceName: new RegExp(esc, "i") },
          { description: new RegExp(esc, "i") },
        ];
      }
      const sortSpec =
        req.query.sort === "price:asc"
          ? { price: 1 }
          : req.query.sort === "price:desc"
            ? { price: -1 }
            : { createdAt: -1 };
      const [items, total] = await Promise.all([
        db
          .collection("services")
          .find(filter)
          .sort(sortSpec)
          .skip(skip)
          .limit(limit)
          .toArray(),
        db.collection("services").countDocuments(filter),
      ]);
      res.json({
        success: true,
        data: {
          services: items.map(serializeService),
          meta: {
            page,
            limit,
            total,
            totalPages: Math.max(1, Math.ceil(total / limit)),
          },
        },
      });
    });

    app.get(
      "/api/services/mine",
      authenticate,
      requireRole("vendor"),
      async (req, res) => {
        const items = await db
          .collection("services")
          .find({ vendorId: String(req.user.id) })
          .sort({ createdAt: -1 })
          .toArray();
        res.json({
          success: true,
          data: { services: items.map(serializeService), categories: CATEGORIES },
        });
      },
    );

    app.get("/api/services/:id", async (req, res) => {
      const service = await findService(req.params.id);
      if (
        !service ||
        service.status !== "approved" ||
        service.isActive === false
      ) {
        return res
          .status(404)
          .json({
            success: false,
            message: "Service not found or not available",
          });
      }
      res.json({ success: true, data: { service: serializeService(service) } });
    });

    app.patch(
      "/api/services/:id",
      authenticate,
      requireRole("vendor", "admin"),
      async (req, res) => {
        const service = await findService(req.params.id);
        if (!service)
          return res
            .status(404)
            .json({ success: false, message: "Service not found" });
        if (
          req.user.role === "vendor" &&
          String(service.vendorId) !== String(req.user.id)
        )
          return res.status(403).json({
            success: false,
            message: "You can only edit your own services",
          });

        const patch = {};
        if (req.body.serviceName !== undefined)
          patch.serviceName = String(req.body.serviceName).trim();
        if (req.body.category !== undefined) {
          if (!CATEGORIES.includes(req.body.category))
            return res
              .status(400)
              .json({ success: false, message: "Invalid category" });
          patch.category = req.body.category;
        }
        if (req.body.description !== undefined)
          patch.description = String(req.body.description).trim();
        if (req.body.location !== undefined)
          patch.location = String(req.body.location).trim();
        if (req.body.price !== undefined) {
          const price = Number(req.body.price);
          if (!Number.isFinite(price) || price < 0)
            return res.status(400).json({
              success: false,
              message: "price must be a non-negative number",
            });
          patch.price = price;
        }
        if (req.body.images !== undefined) {
          if (!Array.isArray(req.body.images))
            return res
              .status(400)
              .json({ success: false, message: "images must be an array" });
          patch.images = req.body.images.filter(
            (u) => typeof u === "string" && u.trim(),
          );
        }
        if (req.body.isActive !== undefined)
          patch.isActive = Boolean(req.body.isActive);
        // Major edits go back through admin review.
        if (req.body.resubmit === true) patch.status = "pending";
        patch.updatedAt = new Date();

        await db
          .collection("services")
          .updateOne({ _id: service._id }, { $set: patch });
        res.json({
          success: true,
          data: { service: serializeService(await findService(service._id)) },
          message: "Service updated",
        });
      },
    );

    app.delete(
      "/api/services/:id",
      authenticate,
      requireRole("vendor", "admin"),
      async (req, res) => {
        const service = await findService(req.params.id);
        if (!service)
          return res
            .status(404)
            .json({ success: false, message: "Service not found" });
        if (
          req.user.role === "vendor" &&
          String(service.vendorId) !== String(req.user.id)
        )
          return res.status(403).json({
            success: false,
            message: "You can only delete your own services",
          });
        await db.collection("services").deleteOne({ _id: service._id });
        await db
          .collection("bookings")
          .deleteMany({ serviceId: String(service._id) });
        res.json({ success: true, message: "Service deleted" });
      },
    );

    app.post(
      "/api/services",
      authenticate,
      requireRole("vendor"),
      async (req, res) => {
        const { serviceName, category, description, price, location } =
          req.body;
        if (!serviceName || !category || !description || !price || !location) {
          return res
            .status(400)
            .json({ success: false, message: "Missing required fields" });
        }
        const categories = CATEGORIES;
        if (!categories.includes(category)) {
          return res
            .status(400)
            .json({ success: false, message: "Invalid category" });
        }
        const numericPrice = Number(price);
        if (!Number.isFinite(numericPrice) || numericPrice < 0) {
          return res
            .status(400)
            .json({
              success: false,
              message: "price must be a non-negative number",
            });
        }

        const isPremiumUser = (u) =>
          u?.subscriptionPlan === "premium" &&
          (!u.subscriptionExpiresAt ||
            new Date(u.subscriptionExpiresAt) > new Date());

        if (!isPremiumUser(req.user)) {
          const count = await db
            .collection("services")
            .countDocuments({
              vendorId: String(req.user.id),
              isActive: true,
              status: { $ne: "rejected" },
            });
          if (count >= 6) {
            return res.status(403).json({
              success: false,
              message:
                "Free plan allows a maximum of 6 active services. Upgrade to Premium (15 days) for more services.",
            });
          }
        }

        const images = Array.isArray(req.body.images)
          ? req.body.images.filter((u) => typeof u === "string" && u.trim())
          : [];
        const now = new Date();
        const { insertedId } = await db.collection("services").insertOne({
          vendorId: String(req.user.id),
          serviceName: String(serviceName).trim(),
          category,
          description: String(description).trim(),
          price: numericPrice,
          location: String(location).trim(),
          images,
          vendorSnapshot: {
            name: req.user.name,
            businessName: req.user.businessName ?? null,
            image: req.user.image ?? null,
          },
          status: "pending",
          isActive: true,
          createdAt: now,
          updatedAt: now,
        });
        res
          .status(201)
          .json({
            success: true,
            data: { service: serializeService(await findService(insertedId)) },
            message: "Service submitted for review",
          });
      },
    );

    app.post(
      "/api/bookings",
      authenticate,
      requireRole("customer"),
      async (req, res) => {
        if (req.user.role === "admin")
          return res
            .status(403)
            .json({
              success: false,
              message: "Admins cannot submit booking requests",
            });
        const { serviceId, eventDate, eventLocation, message } = req.body;
        if (!serviceId || !eventDate || !eventLocation)
          return res
            .status(400)
            .json({ success: false, message: "Missing required fields" });

        const service = await findService(serviceId);
        if (
          !service ||
          service.status !== "approved" ||
          service.isActive === false
        ) {
          return res
            .status(400)
            .json({
              success: false,
              message: "This service is not available for booking",
            });
        }
        if (String(service.vendorId) === String(req.user.id)) {
          return res
            .status(400)
            .json({
              success: false,
              message: "You cannot book your own service",
            });
        }
        const parsedEventDate = new Date(req.body.eventDate);
        if (Number.isNaN(parsedEventDate.getTime()))
          return res
            .status(400)
            .json({
              success: false,
              message: "eventDate must be a valid date",
            });

        const now = new Date();

        const dup = await db.collection("bookings").findOne({
          serviceId: String(service._id),
          customerId: String(req.user.id),
          eventDate,
          status: "pending",
        });
        if (dup)
          return res
            .status(409)
            .json({
              success: false,
              message:
                "You already have a pending request for this service on that date",
            });

        const { insertedId } = await db.collection("bookings").insertOne({
          serviceId: String(service._id),
          vendorId: String(service.vendorId),
          customerId: String(req.user.id),
          eventDate,
          eventLocation: String(req.body.eventLocation).trim(),
          message: req.body.message ? String(req.body.message).trim() : "",
          status: "pending",
          createdAt: now,
          updatedAt: now,
        });
        const bookingDoc = {
          _id: insertedId,
          serviceId: String(service._id),
          vendorId: String(service.vendorId),
          customerId: String(req.user.id),
          eventDate,
          eventLocation: String(req.body.eventLocation).trim(),
          message: req.body.message ? String(req.body.message).trim() : "",
          status: "pending",
          createdAt: now,
        };
        res
          .status(201)
          .json({
            success: true,
            data: { booking: serializeBooking(bookingDoc) },
            message: "Booking request submitted",
          });
      },
    );

    app.get(
      "/api/bookings/vendor",
      authenticate,
      requireRole("vendor"),
      async (req, res) => {
        const page = Math.max(1, Number.parseInt(req.query.page) || 1);
        const limit = Math.min(
          50,
          Math.max(1, Number.parseInt(req.query.limit) || 12),
        );
        const skip = (page - 1) * limit;
        const filter = { vendorId: String(req.user.id) };
        if (req.query.status) filter.status = req.query.status;
        const [items, total] = await Promise.all([
          db
            .collection("bookings")
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
          db.collection("bookings").countDocuments(filter),
        ]);
        const bookings = await enrichBookings(items);
        res.json({
          success: true,
          data: {
            bookings,
            meta: {
              page,
              limit,
              total,
              totalPages: Math.max(1, Math.ceil(total / limit)),
            },
          },
        });
      },
    );

    const enrichBookings = async (items) =>
      Promise.all(
        items.map(async (b) => {
          const service = await findService(String(b.serviceId));
          const customer = await findUser(String(b.customerId));
          return { ...b, id: String(b._id), service, customer };
        }),
      );

    app.get(
      "/api/bookings/mine",
      authenticate,
      requireRole("customer"),
      async (req, res) => {
        const page = Math.max(1, Number.parseInt(req.query.page) || 1);
        const limit = Math.min(
          50,
          Math.max(1, Number.parseInt(req.query.limit) || 12),
        );
        const skip = (page - 1) * limit;
        const filter = { customerId: String(req.user.id) };
        if (req.query.status) filter.status = req.query.status;
        const [items, total] = await Promise.all([
          db
            .collection("bookings")
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
          db.collection("bookings").countDocuments(filter),
        ]);
        res.json({
          success: true,
          data: {
            bookings: await enrichBookings(items),
            meta: {
              page,
              limit,
              total,
              totalPages: Math.max(1, Math.ceil(total / limit)),
            },
          },
        });
      },
    );

    app.patch(
      "/api/bookings/:id/cancel",
      authenticate,
      requireRole("customer"),
      async (req, res) => {
        const booking = ObjectId.isValid(req.params.id)
          ? await db
              .collection("bookings")
              .findOne({ _id: new ObjectId(req.params.id) })
          : null;
        if (!booking)
          return res
            .status(404)
            .json({ success: false, message: "Booking not found" });
        if (String(booking.customerId) !== String(req.user.id))
          return res
            .status(403)
            .json({
              success: false,
              message: "You can only cancel your own bookings",
            });
        if (booking.status !== "pending")
          return res
            .status(409)
            .json({
              success: false,
              message: `Cannot cancel a booking that is already ${booking.status}`,
            });
        await db
          .collection("bookings")
          .updateOne(
            { _id: booking._id },
            { $set: { status: "cancelled", updatedAt: new Date() } },
          );
        res.json({
          success: true,
          data: {
            booking: { ...serializeBooking(booking), status: "cancelled" },
          },
          message: "Booking cancelled",
        });
      },
    );

    app.patch(
      "/api/bookings/:id/respond",
      authenticate,
      requireRole("vendor"),
      async (req, res) => {
        const booking = ObjectId.isValid(req.params.id)
          ? await db
              .collection("bookings")
              .findOne({ _id: new ObjectId(req.params.id) })
          : null;
        if (!booking)
          return res
            .status(404)
            .json({ success: false, message: "Booking not found" });
        if (String(booking.vendorId) !== String(req.user.id))
          return res
            .status(403)
            .json({
              success: false,
              message: "You can only manage requests for your own services",
            });
        if (booking.status !== "pending")
          return res
            .status(409)
            .json({
              success: false,
              message: `This request was already ${booking.status}`,
            });
        const action = String(req.body.action || "").toLowerCase();
        if (!["accept", "reject"].includes(action))
          return res
            .status(400)
            .json({
              success: false,
              message: 'action must be "accept" or "reject"',
            });
        await db
          .collection("bookings")
          .updateOne(
            { _id: booking._id },
            {
              $set: {
                status: action === "accept" ? "accepted" : "rejected",
                updatedAt: new Date(),
              },
            },
          );
        res.json({
          success: true,
          data: {
            booking: {
              ...serializeBooking(booking),
              status: action === "accept" ? "accepted" : "rejected",
            },
          },
          message: `Booking ${action}ed`,
        });
      },
    );

    const customerBookingStats = async (customerId) => {
      const [total, pending, accepted, rejected] = await Promise.all([
        db
          .collection("bookings")
          .countDocuments({ customerId: String(customerId) }),
        db
          .collection("bookings")
          .countDocuments({
            customerId: String(customerId),
            status: "pending",
          }),
        db
          .collection("bookings")
          .countDocuments({
            customerId: String(customerId),
            status: "accepted",
          }),
        db
          .collection("bookings")
          .countDocuments({
            customerId: String(customerId),
            status: "rejected",
          }),
      ]);
      return {
        totalBookings: total,
        pendingBookings: pending,
        acceptedBookings: accepted,
        rejectedBookings: rejected,
      };
    };

    const vendorStats = async (vendorId) => {
      const [totalServices, activeServices, pendingRequests, acceptedBookings] =
        await Promise.all([
          db.collection("services").countDocuments({ vendorId: String(vendorId) }),
          db.collection("services").countDocuments({
            vendorId: String(vendorId),
            status: "approved",
            isActive: true,
          }),
          db.collection("bookings").countDocuments({
            vendorId: String(vendorId),
            status: "pending",
          }),
          db.collection("bookings").countDocuments({
            vendorId: String(vendorId),
            status: "accepted",
          }),
        ]);
      return { totalServices, activeServices, pendingRequests, acceptedBookings };
    };

    app.get(
      "/api/vendor/stats",
      authenticate,
      requireRole("vendor"),
      async (req, res) => {
        const stats = await vendorStats(req.user.id);
        res.json({
          success: true,
          data: {
            ...stats,
            subscriptionPlan: req.user.subscriptionPlan ?? "free",
            subscriptionExpiresAt: req.user.subscriptionExpiresAt ?? null,
          },
        });
      },
    );

    app.get(
      "/api/customer/stats",
      authenticate,
      requireRole("customer"),
      async (req, res) => {
        res.json({
          success: true,
          data: await customerBookingStats(req.user.id),
        });
      },
    );

    app.get(
      "/api/admin/stats",
      authenticate,
      requireRole("admin"),
      async (_req, res) => {
        const [
          totalUsers,
          totalVendors,
          totalCustomers,
          totalServices,
          pendingServices,
          totalTransactions,
        ] = await Promise.all([
          countUsers(),
          countUsers({ role: "vendor" }),
          countUsers({ role: "customer" }),
          db.collection("services").countDocuments(),
          db.collection("services").countDocuments({ status: "pending" }),
          db.collection("transactions").countDocuments(),
        ]);
        res.json({
          success: true,
          data: {
            totalUsers,
            totalVendors,
            totalCustomers,
            totalServices,
            pendingServices,
            totalTransactions,
          },
        });
      },
    );

    app.get(
      "/api/admin/users",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const page = Math.max(1, Number.parseInt(req.query.page) || 1);
        const limit = Math.min(
          50,
          Math.max(1, Number.parseInt(req.query.limit) || 20),
        );
        const skip = (page - 1) * limit;
        const filter = {};
        if (
          req.query.role &&
          ["customer", "vendor", "admin"].includes(req.query.role)
        )
          filter.role = req.query.role;
        if (req.query.blocked === "true") filter.isBlocked = true;
        if (req.query.blocked === "false") filter.isBlocked = false;
        if (req.query.q || req.query.search) {
          const esc = escapeRegex(String(req.query.q || req.query.search));
          filter.$or = [
            { name: new RegExp(esc, "i") },
            { email: new RegExp(esc, "i") },
          ];
        }
        const [items, total] = await Promise.all([
          db
            .collection("user")
            .find(filter)
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
          db.collection("user").countDocuments(filter),
        ]);
        const users = items.map((u) => ({
          id: String(u._id ?? u.id),
          name: u.name,
          email: u.email,
          image: u.image ?? null,
          role: u.role ?? "customer",
          isBlocked: Boolean(u.isBlocked),
          businessName: u.businessName ?? null,
          subscriptionPlan: u.subscriptionPlan ?? "free",
          createdAt: u.createdAt ?? null,
        }));
        res.json({
          success: true,
          data: {
            users,
            meta: {
              page,
              limit,
              total,
              totalPages: Math.max(1, Math.ceil(total / limit)),
            },
          },
        });
      },
    );

    app.get(
      "/api/admin/users/:id",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const user = await findUser(req.params.id);
        if (!user)
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        const { _id, ...rest } = user;
        res.json({
          success: true,
          data: { user: { id: String(_id ?? user.id), ...rest } },
        });
      },
    );

    app.patch(
      "/api/admin/users/:id/block",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const user = await findUser(req.params.id);
        if (!user)
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        if (String(user._id ?? user.id) === String(req.user.id))
          return res
            .status(400)
            .json({
              success: false,
              message: "You cannot block your own account",
            });
        if (user.role === "admin")
          return res
            .status(400)
            .json({
              success: false,
              message: "Admin accounts cannot be blocked",
            });
        const blocked =
          req.path.endsWith("/block") || req.body.blocked === true;
        await db
          .collection("user")
          .updateOne(userQuery(req.params.id), {
            $set: { isBlocked: blocked, updatedAt: new Date() },
          });
        res.json({
          success: true,
          data: { id: req.params.id, isBlocked: blocked },
          message: blocked ? "User blocked" : "User unblocked",
        });
      },
    );

    app.patch(
      "/api/admin/users/:id/unblock",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const user = await findUser(req.params.id);
        if (!user)
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        await db.collection("user").updateOne(userQuery(req.params.id), {
          $set: { isBlocked: false, updatedAt: new Date() },
        });
        res.json({
          success: true,
          data: { id: req.params.id, isBlocked: false },
          message: "User unblocked",
        });
      },
    );

    app.patch(
      "/api/admin/users/:id/role",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const target = await findUser(req.params.id);
        if (!target)
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        const targetId = String(target._id ?? target.id);
        if (targetId === String(req.user.id))
          return res
            .status(400)
            .json({
              success: false,
              message: "You cannot change your own role",
            });
        const role = String(req.body.role ?? "");
        if (!["customer", "vendor", "admin"].includes(role))
          return res
            .status(400)
            .json({
              success: false,
              message: 'role must be one of "customer", "vendor", "admin"',
            });
        const current = target.role ?? "customer";
        if (current === role)
          return res.json({
            success: true,
            data: { id: targetId, role },
            message: "Role unchanged",
          });
        if (current === "admin") {
          const admins = await countUsers({ role: "admin" });
          if (admins <= 1)
            return res
              .status(409)
              .json({
                success: false,
                message: "Cannot demote the last remaining admin",
              });
        }
        await db
          .collection("user")
          .updateOne(userQuery(targetId), {
            $set: { role, updatedAt: new Date() },
          });
        res.json({
          success: true,
          data: { id: targetId, role },
          message: `Role updated to ${role}`,
        });
      },
    );

    app.delete(
      "/api/admin/users/:id",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const target = await findUser(req.params.id);
        if (!target)
          return res
            .status(404)
            .json({ success: false, message: "User not found" });
        const targetId = String(target._id ?? target.id);
        if (targetId === String(req.user.id))
          return res
            .status(400)
            .json({
              success: false,
              message: "You cannot delete your own account",
            });
        if ((target.role ?? "customer") === "admin") {
          const admins = await countUsers({ role: "admin" });
          if (admins <= 1)
            return res
              .status(409)
              .json({
                success: false,
                message: "Cannot delete the last remaining admin",
              });
        }
        const idStr = String(target._id ?? target.id);
        const ids = [idStr];
        if (ObjectId.isValid(idStr)) ids.push(new ObjectId(idStr));
        await Promise.all([
          db.collection("user").deleteOne(userQuery(targetId)),
          db.collection("session").deleteMany({ userId: { $in: ids } }),
          db.collection("account").deleteMany({ userId: { $in: ids } }),
          db
            .collection("verification")
            .deleteMany({ identifier: target.email }),
        ]);
        res.json({
          success: true,
          data: { id: targetId },
          message: "User deleted permanently",
        });
      },
    );

    app.get(
      "/api/admin/services",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const page = Math.max(1, Number.parseInt(req.query.page) || 1);
        const limit = Math.min(
          50,
          Math.max(1, Number.parseInt(req.query.limit) || 12),
        );
        const { items, total } = await findServicesFiltered({
          approvedOnly: false,
          query: req.query.q,
          category: req.query.category,
          location: req.query.location,
          status: req.query.status,
          sort: req.query.sort
            ? (() => {
                const s = String(req.query.sort).toLowerCase();
                if (s === "price:asc") return { price: 1 };
                if (s === "price:desc") return { price: -1 };
                if (s === "createdat:asc") return { createdAt: 1 };
                return { createdAt: -1 };
              })()
            : { createdAt: -1 },
          skip: (page - 1) * limit,
          limit,
        });
        res.json({
          success: true,
          data: {
            services: items,
            meta: {
              page,
              limit,
              total,
              totalPages: Math.max(1, Math.ceil(total / limit)),
            },
          },
        });
      },
    );

    app.patch(
      "/api/admin/services/:id/status",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const service = ObjectId.isValid(req.params.id)
          ? await db
              .collection("services")
              .findOne({ _id: new ObjectId(req.params.id) })
          : null;
        if (!service)
          return res
            .status(404)
            .json({ success: false, message: "Service not found" });
        const status = String(req.body.status || "");
        if (!["approved", "rejected"].includes(status))
          return res
            .status(400)
            .json({
              success: false,
              message: 'status must be "approved" or "rejected"',
            });
        const updatedAt = new Date();
        await db
          .collection("services")
          .updateOne(
            { _id: service._id },
            {
              $set: {
                status,
                isActive:
                  status === "approved" ? true : Boolean(service.isActive),
                updatedAt,
              },
            },
          );
        res.json({
          success: true,
          data: { service: serializeService(await findService(service._id)) },
          message: `Service ${status}`,
        });
      },
    );

    app.get(
      "/api/admin/transactions",
      authenticate,
      requireRole("admin"),
      async (req, res) => {
        const page = Math.max(1, Number.parseInt(req.query.page) || 1);
        const limit = Math.min(
          50,
          Math.max(1, Number.parseInt(req.query.limit) || 20),
        );
        const skip = (page - 1) * limit;
        const [items, total] = await Promise.all([
          db
            .collection("transactions")
            .find()
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray(),
          db.collection("transactions").countDocuments(),
        ]);
        const vendorIds = [...new Set(items.map((t) => String(t.vendorId)))];
        const userDocs = vendorIds.length
          ? await db
              .collection("user")
              .find({
                $or: vendorIds.flatMap((id) => [
                  { _id: id },
                  ...(ObjectId.isValid(id) ? [{ _id: new ObjectId(id) }] : []),
                  { id },
                ]),
              })
              .toArray()
          : [];
        const userMap = new Map(
          userDocs.map((u) => [String(u._id ?? u.id), u]),
        );
        const transactions = items.map((t) => {
          const u = userMap.get(String(t.vendorId));
          return {
            ...t,
            id: String(t._id),
            vendor: u
              ? {
                  id: String(u._id ?? u.id),
                  name: u.name,
                  email: u.email,
                  businessName: u.businessName ?? null,
                }
              : null,
          };
        });
        res.json({
          success: true,
          data: {
            transactions,
            meta: {
              page,
              limit,
              total,
              totalPages: Math.max(1, Math.ceil(total / limit)),
            },
          },
        });
      },
    );

    // --- Subscriptions & Stripe ---
    app.get("/api/subscriptions/plans", (_req, res) => {
      res.json({
        success: true,
        data: {
          plans: [
            {
              id: "free",
              name: "Free",
              price: 0,
              currency: stripeConfig.premiumCurrency,
              features: [
                "Up to 6 active services",
                "Basic vendor dashboard",
                "Booking request management",
              ],
            },
            {
              id: "premium",
              name: "Premium (15 days)",
              price: stripeConfig.premiumAmount / 100,
              currency: stripeConfig.premiumCurrency,
              days: stripeConfig.premiumDurationDays,
              features: [
                "Unlimited active services",
                "Premium vendor badge",
                "Everything in Free",
              ],
            },
          ],
        },
      });
    });

    app.get(
      "/api/subscriptions/status",
      authenticate,
      requireRole("vendor"),
      (req, res) => {
        res.json({
          success: true,
          data: {
            plan: req.user.subscriptionPlan,
            subscriptionExpiresAt: req.user.subscriptionExpiresAt,
            isPremium: isPremiumUser(req.user),
          },
        });
      },
    );

    app.post(
      "/api/subscriptions/checkout",
      authenticate,
      requireRole("vendor"),
      async (req, res) => {
        if (!stripe)
          return res
            .status(501)
            .json({
              success: false,
              message: "Stripe is not configured on this server",
            });
        if (
          req.body.vendorId &&
          String(req.body.vendorId) !== String(req.user.id)
        )
          return res
            .status(403)
            .json({
              success: false,
              message: "You cannot create a subscription for another vendor",
            });
        const vendorId = String(req.user.id);
        const planType = req.body.planType || "premium";
        const planKey = "premium";
        const success_url = `http://localhost:3000/payment/success?session_id={CHECKOUT_SESSION_ID}`;
        const cancel_url = `http://localhost:3000/payment/cancel`;
        const params = {
          mode: stripeConfig.priceId ? "subscription" : "payment",
          success_url: success_url,
          cancel_url: cancel_url,
          client_reference_id: vendorId,
          metadata: { vendorId, planType },
          ...(req.user.email ? { customer_email: req.user.email } : {}),
          line_items: [
            stripeConfig.priceId
              ? { price: stripeConfig.priceId }
              : {
                  price_data: {
                    currency: stripeConfig.premiumCurrency,
                    unit_amount: stripeConfig.premiumAmount,
                    product_data: {
                      name: `WedPlan Premium (${stripeConfig.premiumDurationDays} days)`,
                      metadata: { vendorId, planType },
                    },
                  },
                  quantity: 1,
                },
          ],
        };
        const session = await stripe.checkout.sessions.create(params);
        res.json({
          success: true,
          data: { url: session.url, sessionId: session.id },
        });
      },
    );

    app.post(
      "/api/subscriptions/checkout-verify",
      authenticate,
      requireRole("vendor"),
      async (req, res) => {
        if (!stripe)
          return res
            .status(501)
            .json({
              success: false,
              message: "Stripe is not configured on this server",
            });
        const { sessionId } = req.body;
        if (!sessionId)
          return res.json({
            success: false,
            message: "Session ID is required",
          });
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (
          session.status !== "complete" ||
          session.payment_status !== "paid"
        ) {
          return res.json({
            success: false,
            message: "Payment verification failed",
          });
        }
        const vendorId =
          session.metadata?.vendorId || session.client_reference_id;
        const planType = session.metadata?.planType || "premium";
        if (!vendorId)
          return res
            .status(400)
            .json({
              success: false,
              message: "No vendorId on the Stripe session",
            });
        if (String(vendorId) !== String(req.user.id))
          return res
            .status(403)
            .json({
              success: false,
              message: "You cannot verify a payment for another vendor",
            });

        const existingUser = await findUser(vendorId);
        const existingExpiresAt = existingUser.subscriptionExpiresAt
          ? new Date(existingUser.subscriptionExpiresAt)
          : null;
        const newExpiresAt = new Date(
          Date.now() + stripeConfig.premiumDurationDays * 24 * 60 * 60 * 1000,
        );
        const expiresAt =
          existingExpiresAt && existingExpiresAt > newExpiresAt
            ? existingExpiresAt
            : newExpiresAt;

        const planKey = "premium";
        await db.collection("transactions").insertOne({
          vendorId: String(vendorId),
          plan: planType,
          amount: (session.amount_total ?? stripeConfig.premiumAmount) / 100,
          currency: session.currency ?? stripeConfig.premiumCurrency,
          stripeSessionId: sessionId,
          stripeSubscriptionId:
            typeof session.subscription === "string"
              ? session.subscription
              : null,
          stripeEventId: `checkout-${sessionId}`,
          status: "succeeded",
          createdAt: new Date(),
        });
        await db
          .collection("user")
          .updateOne(userQuery(vendorId), {
            $set: {
              subscriptionPlan: planType,
              subscriptionExpiresAt: expiresAt,
              updatedAt: new Date(),
            },
          });
        res.json({
          success: true,
          data: { verified: true, plan: planType, expiresAt },
          message: "Payment verified",
        });
      },
    );

    async function handleStripeWebhook(req, res) {
      if (!Buffer.isBuffer(req.rawBody))
        return res
          .status(400)
          .json({ success: false, message: "Expected raw body" });
      try {
        if (!verifyStripeSignature(req.rawBody, req.headers["stripe-signature"])) {
          return res
            .status(400)
            .json({
              success: false,
              message: "Invalid Stripe webhook signature",
            });
        }
      } catch (err) {
        return res.status(400).json({ success: false, message: err.message });
      }
      const event = JSON.parse(req.rawBody.toString("utf8"));
      const object = event?.data?.object ?? {};
      if (event.type === "checkout.session.completed") {
        const vendorId =
          object.metadata?.vendorId || object.client_reference_id;
        const planType = "premium";
        if (vendorId) {
          const existingUser = await findUser(vendorId);
          const existingExpiresAt = existingUser.subscriptionExpiresAt
            ? new Date(existingUser.subscriptionExpiresAt)
            : null;
          const newExpiresAt = new Date(
            Date.now() + stripeConfig.premiumDurationDays * 24 * 60 * 60 * 1000,
          );
          const expiresAt =
            existingExpiresAt && existingExpiresAt > newExpiresAt
              ? existingExpiresAt
              : newExpiresAt;

          const existing = await db
            .collection("transactions")
            .findOne({ stripeEventId: event.id });
          if (!existing) {
            await db.collection("transactions").insertOne({
              vendorId: String(vendorId),
              plan: planType,
              amount: (object.amount_total ?? stripeConfig.premiumAmount) / 100,
              currency: object.currency ?? stripeConfig.premiumCurrency,
              stripeSessionId: object.id,
              stripeSubscriptionId:
                typeof object.subscription === "string"
                  ? object.subscription
                  : null,
              stripeEventId: event.id,
              status: "succeeded",
              createdAt: new Date(),
            });
            await db
              .collection("user")
              .updateOne(userQuery(vendorId), {
                $set: {
                  subscriptionPlan: planType,
                  subscriptionExpiresAt: expiresAt,
                  updatedAt: new Date(),
                },
              });
          }
        }
      } else if (event.type === "customer.subscription.deleted") {
        await db
          .collection("transactions")
          .updateMany(
            { stripeSubscriptionId: object.id },
            { $set: { status: "cancelled" } },
          );
        await db
          .collection("user")
          .updateMany(
            { stripeSubscriptionId: object.id },
            {
              $set: {
                subscriptionPlan: "free",
                subscriptionExpiresAt: null,
                updatedAt: new Date(),
              },
            },
          );
      } else if (event.type === "invoice.payment_failed") {
        if (typeof object.subscription === "string")
          await db
            .collection("transactions")
            .updateMany(
              { stripeSubscriptionId: object.subscription },
              { $set: { status: "failed" } },
            );
      }
      res.json({ success: true, data: { received: true } });
    }

    async function seedSampleData() {
      const now = new Date();
      const existingConfig = await db
        .collection("config")
        .findOne({ _id: "sampleData" });
      if (existingConfig && existingConfig.seeded) {
        const vendor = await db
          .collection("user")
          .findOne({ email: "sample-vendor@wedplan.test" });
        const customer = await db
          .collection("user")
          .findOne({ email: "sample.customer@wedplan.app" });
        if (!vendor || !customer) {
        } else {
          const sampleService = await db
            .collection("services")
            .findOne({ vendorId: vendor._id, status: "approved" });
          if (sampleService) {
            const existingBooking = await db
              .collection("bookings")
              .findOne({
                serviceId: String(sampleService._id),
                customerId: customer._id,
                status: "pending",
              });
            if (!existingBooking) {
              await db.collection("bookings").insertOne({
                serviceId: String(sampleService._id),
                vendorId: String(vendor._id),
                customerId: customer._id,
                eventDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
                eventLocation: sampleService.location,
                message:
                  "Congratulations! Excited to celebrate this milestone with you.",
                status: "pending",
                createdAt: now,
                updatedAt: now,
              });
            }
          }
          return;
        }
      }

      const vendorEmail = "sample-vendor@wedplan.test";
      let vendor = await db.collection("user").findOne({ email: vendorEmail });
      let vendorId;
      if (!vendor) {
        const { insertedId } = await db.collection("user").insertOne({
          name: "Sample Vendor",
          email: vendorEmail,
          image: null,
          role: "vendor",
          businessName: "WedPlan Wedding Studio",
          subscriptionPlan: "premium",
          subscriptionExpiresAt: new Date(
            Date.now() + PREMIUM_DURATION_DAYS * 24 * 60 * 60 * 1000,
          ),
          isBlocked: false,
          createdAt: now,
          updatedAt: now,
        });
        vendorId = String(insertedId);
      } else {
        vendorId = String(vendor._id ?? vendor.id);
      }

     
      const catalogDocs = await serviceCatalog.find().toArray();
      const existingServiceNames = new Set(
        (
          await db
            .collection("services")
            .find({ vendorId })
            .project({ serviceName: 1 })
            .toArray()
        ).map((s) => s.serviceName),
      );
      for (const entry of catalogDocs) {
        if (existingServiceNames.has(entry.serviceName)) continue;
        await db.collection("services").insertOne({
          vendorId,
          serviceName: entry.serviceName,
          category: entry.category,
          description: entry.description,
          price: entry.price,
          location: entry.location,
          images: entry.images ?? [],
          vendorSnapshot: {
            name: vendor?.name ?? "Sample Vendor",
            businessName: vendor?.businessName ?? null,
            image: vendor?.image ?? null,
          },
          status: "approved",
          isActive: true,
          createdAt: now,
          updatedAt: now,
        });
        existingServiceNames.add(entry.serviceName);
      }

      const customerEmail = "sample.customer@wedplan.app";
      let customer = await db
        .collection("user")
        .findOne({ email: customerEmail });
      let customerId;
      if (!customer) {
        const { insertedId } = await db.collection("user").insertOne({
          name: "Sample Customer",
          email: customerEmail,
          image: null,
          role: "customer",
          isBlocked: false,
          createdAt: now,
          updatedAt: now,
        });
        customerId = String(insertedId);
      } else {
        customerId = String(customer._id ?? customer.id);
      }

      const sampleService = await db
        .collection("services")
        .findOne({ vendorId, status: "approved" });
      if (sampleService) {
        const existingBooking = await db
          .collection("bookings")
          .findOne({
            serviceId: String(sampleService._id),
            customerId,
            status: "pending",
          });
        if (!existingBooking) {
          await db.collection("bookings").insertOne({
            serviceId: String(sampleService._id),
            vendorId,
            customerId,
            eventDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
            eventLocation: sampleService.location,
            message:
              "Congratulations! Excited to celebrate this milestone with you.",
            status: "pending",
            createdAt: now,
            updatedAt: now,
          });
        }
      }

      await db
        .collection("config")
        .updateOne(
          { _id: "sampleData" },
          { $set: { seeded: true } },
          { upsert: true },
        );
    }

    async function seedAdmin() {
      const email = process.env.ADMIN_SEED_EMAIL;
      if (!email)
        throw new Error("ADMIN_SEED_EMAIL must be set to seed an admin user");
      const now = new Date();
      const existing = await db.collection("user").findOne({ email });
      if (!existing) {
        await db.collection("user").insertOne({
          name: "WedPlan Admin",
          email,
          image: null,
          role: "admin",
          isBlocked: false,
          createdAt: now,
          updatedAt: now,
        });
        console.log(`Admin user seeded for ${email}`);
        return;
      }
      await db
        .collection("user")
        .updateOne(userQuery(String(existing._id ?? existing.id)), {
          $set: { role: "admin", updatedAt: now },
        });
      console.log(`Admin ensured for ${email}`);
    }

   
    app.get("/api/health", (_req, res) => {
      res.json({ success: true, status: "ok" });
    });

    app.use("/api", (req, res) =>
      res.status(404).json({
        success: false,
        message: `Endpoint not found: ${req.method} ${req.originalUrl}`,
      }),
    );

    app.use((err, _req, res, _next) => {
      console.error("[server] request error:", err);
      res.status(500).json({
        success: false,
        message: "Internal server error",
      });
    });

    async function main() {
      if (process.argv.includes("--seed")) {
        await seedSampleData();
        process.exit(0);
      }
      if (process.argv.includes("--seed-admin")) {
        await seedAdmin();
        process.exit(0);
      }
      server = app.listen(port, () =>
        console.log(`WedPlan Server is Running on port ${port}`),
      );
    }

    main().catch((err) => {
      console.error("[fatal]", err);
      process.exit(1);
    });

    const shutdown = async (signal) => {
      console.log(`\n[server] ${signal} received — shutting down`);
      try {
        if (server) await new Promise((r) => server.close(r));
        await client.close();
        process.exit(0);
      } catch (err) {
        console.error("[server] error during shutdown:", err);
        process.exit(1);
      }
    };

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

