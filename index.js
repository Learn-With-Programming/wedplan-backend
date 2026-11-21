import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";
import crypto from "node:crypto";
import Stripe from "stripe";

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());

app.use(express.json());

const client = new MongoClient(`mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASS}@cluster0.cejh16o.mongodb.net/`);
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

const JWT_JWKS_URL = process.env.JWKS_URL || "http://localhost:3000/api/auth/jwks";

async function verifyJwt(token) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("Malformed token");
  const [header, payload, signature] = parts;
  const decodedHeader = JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
  const keysRes = await fetch(JWT_JWKS_URL);
  if (!keysRes.ok) throw new Error(`Failed to fetch JWKS (HTTP ${keysRes.status})`);
  const jwk = (await keysRes.json()).keys?.find((k) => k.kid === decodedHeader.kid);
  if (!jwk) throw new Error("No matching key in JWKS");
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const valid = crypto.verify(null, Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, "base64url"));
  if (!valid) throw new Error("Invalid token signature");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  if (claims.exp && claims.exp < Math.floor(Date.now() / 1000)) throw new Error("Token expired");
  const userId = claims.sub || claims.userId || claims.id;
  if (!userId) throw new Error("Token is missing the subject");
  return { userId: String(userId) };
};

const CATEGORIES = [
  "Photography & Videography",
  "Wedding Venues",
  "Decoration & Florist",
  "Catering Services",
  "Makeup & Styling",
  "Wedding Fashion",
];

const escapeRegex = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const findUser = (id) => db.collection("user").findOne(userQuery(String(id)));
const countUsers = (filter = {}) => db.collection("user").countDocuments(filter);
const findService = (id) =>
  ObjectId.isValid(id)
    ? db.collection("services").findOne({ _id: new ObjectId(id) })
    : null;

const serializeCatalogEntry = (e) => e && { ...e, id: String(e._id) };

const serializeService = (s) =>
  s && { ...s, id: String(s._id) };

const verifyStripeSignature = (rawBody, signatureHeader) => {
  const parts = String(signatureHeader || "")
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean);
  const timestampPart = parts.find((p) => p.startsWith("t="));
  const signaturePart = parts.find((p) => p.startsWith("v1="));
  if (!timestampPart || !signaturePart) return false;
  const timestamp = Number(timestampPart.slice(2));
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > 300)
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

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user)
    return res
      .status(401)
      .json({ success: false, message: "Authentication required" });
  if (!roles.includes(req.user.role))
    return res
      .status(403)
      .json({ success: false, message: "Forbidden" });
  app.get("/api/services/meta", (req, res) => {
  res.json({
    success: true,
    data: {
      categories: CATEGORIES,
    },
  });
});

app.get("/api/services/catalog", authenticate, requireRole("admin"), async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page) || 1);
  const limit = Math.min(50, Math.max(1, Number.parseInt(req.query.limit) || 25));
  const skip = (page - 1) * limit;
  const filter = {};
  if (req.query.q) filter.serviceName = new RegExp(escapeRegex(String(req.query.q)), "i");
  const [items, total] = await Promise.all([
    serviceCatalog.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
    serviceCatalog.countDocuments(filter),
  ]);
  res.json({
    success: true,
    data: {
      entries: items.map(serializeCatalogEntry),
      meta: { page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) },
    },
  });
});

app.get("/api/services/catalog/:id", authenticate, requireRole("admin"), async (req, res) => {
  const entry = ObjectId.isValid(req.params.id)
    ? await serviceCatalog.findOne({ _id: new ObjectId(req.params.id) })
    : null;
  if (!entry) return res.status(404).json({ success: false, message: "Catalog entry not found" });
  res.json({ success: true, data: { entry: serializeCatalogEntry(entry) } });
});

app.post("/api/services/catalog", authenticate, requireRole("admin"), async (req, res) => {
  const body = req.body ?? {};
  if (!body.serviceName || !body.category || !body.description || body.price === undefined || !body.location) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }
  if (!CATEGORIES.includes(body.category)) {
    return res.status(400).json({ success: false, message: "Invalid category" });
  }
  const numericPrice = Number(body.price);
  if (!Number.isFinite(numericPrice) || numericPrice < 0) {
    return res.status(400).json({ success: false, message: "price must be a non-negative number" });
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
  res.status(201).json({ success: true, data: { entry: serializeCatalogEntry(entry) }, message: "Catalog entry created" });
});

app.patch("/api/services/catalog/:id", authenticate, requireRole("admin"), async (req, res) => {
  const entry = ObjectId.isValid(req.params.id)
    ? await serviceCatalog.findOne({ _id: new ObjectId(req.params.id) })
    : null;
  if (!entry) return res.status(404).json({ success: false, message: "Catalog entry not found" });
  const patch = {};
  if (req.body.serviceName !== undefined) patch.serviceName = String(req.body.serviceName).trim();
  if (req.body.description !== undefined) patch.description = String(req.body.description).trim();
  if (req.body.location !== undefined) patch.location = String(req.body.location).trim();
  if (req.body.category !== undefined) {
    if (!CATEGORIES.includes(req.body.category)) return res.status(400).json({ success: false, message: "Invalid category" });
    patch.category = req.body.category;
  }
  if (req.body.price !== undefined) {
    const numericPrice = Number(req.body.price);
    if (!Number.isFinite(numericPrice) || numericPrice < 0) {
      return res.status(400).json({ success: false, message: "price must be a non-negative number" });
    }
    patch.price = numericPrice;
  }
  if (req.body.images !== undefined) {
    if (!Array.isArray(req.body.images)) return res.status(400).json({ success: false, message: "images must be an array" });
    patch.images = req.body.images.filter((u) => typeof u === "string" && u.trim());
  }
  if (Object.keys(patch).length > 0) {
    await serviceCatalog.updateOne({ _id: entry._id }, { $set: { ...patch, updatedAt: new Date() } });
  }
  res.json({
    success: true,
    data: { entry: serializeCatalogEntry(await serviceCatalog.findOne({ _id: entry._id })) },
    message: "Catalog entry updated",
  });
});

app.delete("/api/services/catalog/:id", authenticate, requireRole("admin"), async (req, res) => {
  const entry = ObjectId.isValid(req.params.id)
    ? await serviceCatalog.findOne({ _id: new ObjectId(req.params.id) })
    : null;
  if (!entry) return res.status(404).json({ success: false, message: "Catalog entry not found" });
  await serviceCatalog.deleteOne({ _id: entry._id });
  res.json({ success: true, message: "Catalog entry deleted" });
});

app.get("/api/services", async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page) || 1);
  const limit = Math.min(50, Math.max(1, Number.parseInt(req.query.limit) || 12));
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
    db.collection("services")
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
      meta: { page, limit, total, totalPages: Math.max(1, Math.ceil(total / limit)) },
    },
  });
});

app.get("/api/services/:id", async (req, res) => {
  const service = await findService(req.params.id);
  if (!service || service.status !== "approved" || service.isActive === false) {
    return res
      .status(404)
      .json({ success: false, message: "Service not found or not available" });
  }
  res.json({ success: true, data: { service: serializeService(service) } });
});

app.post("/api/services", authenticate, requireRole("vendor"), async (req, res) => {
  const { serviceName, category, description, price, location } = req.body;
  if (!serviceName || !category || !description || !price || !location) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }
  const categories = CATEGORIES;
  if (!categories.includes(category)) {
    return res.status(400).json({ success: false, message: "Invalid category" });
  }
  const numericPrice = Number(price);
  if (!Number.isFinite(numericPrice) || numericPrice < 0) {
    return res.status(400).json({ success: false, message: "price must be a non-negative number" });
  }

  const isPremiumUser = (u) => u?.subscriptionPlan === "premium" && (!u.subscriptionExpiresAt || new Date(u.subscriptionExpiresAt) > new Date());

if (!isPremiumUser(req.user)) {
    const count = await db
      .collection("services")
      .countDocuments({ vendorId: String(req.user.id), isActive: true, status: { $ne: "rejected" } });
    if (count >= 6) {
      return res
        .status(403)
        .json({
          success: false,
          message: "Free plan allows a maximum of 6 active services. Upgrade to Premium (15 days) for more services.",
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
    .json({ success: true, data: { service: serializeService(await findService(insertedId)) }, message: "Service submitted for review" });
});

app.get("/api/services/mine", authenticate, requireRole("vendor"), async (req, res) => {
  res.json({
    success: true,
    data: {
      categories: CATEGORIES,
    },
  });
});

app.post("/api/bookings", authenticate, requireRole("customer"), async (req, res) => {