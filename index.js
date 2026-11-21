import express from "express";
import cors from "cors";
import "dotenv/config";
import { MongoClient, ObjectId } from "mongodb";

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