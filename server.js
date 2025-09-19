// server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");

// -------------------------
//  CONFIG
// -------------------------
const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017/fylshare"; // change to your Mongo URI

app.use(cors());
app.use(bodyParser.json());

// -------------------------
//  DB CONNECTION
// -------------------------
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// -------------------------
//  SCHEMA + MODELS
// -------------------------
const FileSchema = new mongoose.Schema({
  code: { type: String, required: true },
  name: { type: String, required: true },
  files: [
    {
      name: String,
      url: String,
    },
  ],
  size: String,
  uploadedBy: String,
  date: { type: Date, default: Date.now },
  type: { type: String, enum: ["general", "room"], default: "general" },
  roomCode: { type: String, default: null }, // only for room uploads
});

const FileUpload = mongoose.model("FileUpload", FileSchema);

// -------------------------
//  ROUTES
// -------------------------

/**
 * Uploads (General)
 */
app.post("/api/uploads", async (req, res) => {
  try {
    const { name, files, code, size } = req.body;
    if (!name || !files || files.length === 0 || !code) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const sizeMB = (size / 1024 / 1024).toFixed(2);

    const uploadEntry = new FileUpload({
      code,
      name,
      files,
      size: sizeMB,
      uploadedBy: name,
      type: "general",
    });

    await uploadEntry.save();
    res.json(uploadEntry);
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Room Uploads
 */
app.post("/api/rooms/upload", async (req, res) => {
  try {
    const { roomCode, name, files, code, size } = req.body;
    if (!roomCode || !name || !files || files.length === 0 || !code) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const sizeMB = (size / 1024 / 1024).toFixed(2);

    const roomEntry = new FileUpload({
      roomCode,
      code,
      name,
      files,
      size: sizeMB,
      uploadedBy: name,
      type: "room",
    });

    await roomEntry.save();
    res.json(roomEntry);
  } catch (err) {
    console.error("Room upload error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Get Upload by Code (for Search)
 */
app.get("/api/uploads/:code", async (req, res) => {
  try {
    const { code } = req.params;
    const found = await FileUpload.findOne({ code });

    if (!found) {
      return res.status(404).json({ error: "No file found for this code" });
    }

    res.json(found);
  } catch (err) {
    console.error("Search error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Get All Uploads (for Admin)
 */
app.get("/api/uploads", async (req, res) => {
  try {
    const allUploads = await FileUpload.find().sort({ date: -1 });
    res.json(allUploads);
  } catch (err) {
    console.error("Admin fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Delete Upload by Code
 */
app.delete("/api/uploads/:code", async (req, res) => {
  try {
    const { code } = req.params;
    const deleted = await FileUpload.findOneAndDelete({ code });

    if (!deleted) {
      return res.status(404).json({ error: "Upload not found" });
    }

    res.json({ success: true, code });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Get Room Uploads (for Room.js)
 */
app.get("/api/rooms/:roomCode", async (req, res) => {
  try {
    const { roomCode } = req.params;
    const files = await FileUpload.find({ roomCode, type: "room" }).sort({
      date: -1,
    });
    res.json(files);
  } catch (err) {
    console.error("Room fetch error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// -------------------------
//  START SERVER
// -------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
