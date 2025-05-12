const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

// ===== MIDDLEWARE =====
app.use(cors({ origin: "https://filehub-gyll.web.app" })); // <- your Firebase Hosting URL
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Serve uploaded files

// ===== CONNECT TO MONGODB =====
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ===== MULTER SETUP =====
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname;
    cb(null, uniqueName);
  },
});
const upload = multer({ storage });

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

// POST: Upload files
app.post("/api/uploads", upload.array("files", 10), async (req, res) => {
  try {
    const { name, code } = req.body;

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    const files = req.files.map((file) => ({
      name: file.originalname,
      url: `${req.protocol}://${req.get("host")}/uploads/${file.filename}`,
    }));

    const totalSize = req.files.reduce((sum, f) => sum + f.size, 0);

    const newUpload = new Upload({ name, code, files, size: totalSize });
    await newUpload.save();

    res.status(201).json({ message: "Upload saved successfully", code });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Failed to save upload" });
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
