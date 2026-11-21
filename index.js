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
  next();
};