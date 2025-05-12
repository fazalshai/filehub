const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

// ===== MIDDLEWARE =====
app.use(cors({ origin: "https://filehub-gyll.web.app" }));
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

// POST: Save metadata from Firebase upload
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

// GET: Retrieve file info by code
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

// GET: All uploads (for admin)
app.get("/api/uploads", async (req, res) => {
  try {
    const uploads = await Upload.find().sort({ date: -1 });
    res.json(uploads);
  } catch (err) {
    console.error("Admin fetch error:", err);
    res.status(500).json({ error: "Failed to fetch uploads" });
  }
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
