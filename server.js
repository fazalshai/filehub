const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

// ===== MIDDLEWARE =====
const allowedOrigins = [
  "https://filehub-gyll.web.app",
  "https://fileverse-krwk3.web.app",
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
  "https://fylshare.com"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    }
  })
);

app.use(express.json());

// ===== CONNECT TO MONGODB =====
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ===== SCHEMA =====
const uploadSchema = new mongoose.Schema({
  name: String,
  files: [
    {
      name: String,
      url: String,
    },
  ],
  code: String,
  size: Number,
  date: { type: Date, default: Date.now },
});

const Upload = mongoose.model("Upload", uploadSchema);

// ===== ROUTES =====

// Create new upload
app.post("/api/uploads", async (req, res) => {
  try {
    const { name, code, files, size } = req.body;

    if (!files || files.length === 0) {
      return res.status(400).json({ error: "No files provided" });
    }

    const newUpload = new Upload({ name, code, files, size });
    await newUpload.save();

    res.status(201).json({ message: "Upload metadata saved", code });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Failed to save upload metadata" });
  }
});

// Get a single upload by code
app.get("/api/uploads/:code", async (req, res) => {
  try {
    const data = await Upload.findOne({ code: req.params.code });
    if (!data) {
      return res.status(404).json({ message: "No file found for this code" });
    }
    res.json(data);
  } catch (error) {
    console.error("Search error:", error);
    res.status(500).json({ error: "Error fetching file" });
  }
});

// Get all uploads (admin use)
app.get("/api/uploads", async (req, res) => {
  try {
    const uploads = await Upload.find().sort({ date: -1 });
    res.json(uploads);
  } catch (err) {
    console.error("Admin fetch error:", err);
    res.status(500).json({ error: "Failed to fetch uploads" });
  }
});

// ===== NEW: DELETE upload by code (for main admin) =====
app.delete("/api/uploads/:code", async (req, res) => {
  try {
    const deleted = await Upload.findOneAndDelete({ code: req.params.code });
    if (!deleted) {
      return res.status(404).json({ message: "No upload found with this code" });
    }
    res.status(200).json({ message: "Upload deleted successfully" });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ error: "Error deleting upload" });
  }
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
