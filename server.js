// server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;

// ===== CORS =====
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3002",
  "https://filehub-gyll.web.app",
  "https://fileverse-krwk3.web.app",
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

// ===== SCHEMAS =====
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

const roomSchema = new mongoose.Schema({
  key: { type: String, unique: true, required: true },
  name: String,
  files: [
    {
      uploader: String,
      name: String,
      url: String,
      size: Number,
      date: { type: Date, default: Date.now },
      code: String, // added to align with uploads
    },
  ],
  createdAt: { type: Date, default: Date.now },
});
const Room = mongoose.model("Room", roomSchema);

// ===== ROUTES =====

// ----------------- Upload Routes -----------------

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

// Get all uploads (Admin)
app.get("/api/uploads", async (req, res) => {
  try {
    const uploads = await Upload.find().sort({ date: -1 });
    res.json(uploads);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch uploads" });
  }
});

// ✅ Get upload by code
app.get("/api/uploads/:code", async (req, res) => {
  try {
    const upload = await Upload.findOne({ code: req.params.code });
    if (!upload) {
      return res.status(404).json({ error: "No file found for this code" });
    }
    res.json(upload);
  } catch (error) {
    console.error("Fetch upload by code error:", error);
    res.status(500).json({ error: "Failed to fetch upload" });
  }
});

// Delete upload by code
app.delete("/api/uploads/:code", async (req, res) => {
  try {
    const deleted = await Upload.findOneAndDelete({ code: req.params.code });
    if (!deleted) {
      return res.status(404).json({ message: "No upload found with this code" });
    }
    res.status(200).json({ message: "Upload deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error deleting upload" });
  }
});

// ----------------- Room Routes -----------------

app.post("/api/rooms/create", async (req, res) => {
  try {
    const { name, key } = req.body;
    const existing = await Room.findOne({ key });
    if (existing) {
      return res.status(400).json({ error: "Room key already exists" });
    }
    const newRoom = new Room({ name, key, files: [] });
    await newRoom.save();
    res.status(201).json({ message: "Room created", room: newRoom });
  } catch (error) {
    res.status(500).json({ error: "Failed to create room" });
  }
});

app.post("/api/rooms/open", async (req, res) => {
  try {
    const { key } = req.body;
    const room = await Room.findOne({ key });
    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }
    res.status(200).json({ message: "Room opened", room });
  } catch (error) {
    res.status(500).json({ error: "Failed to open room" });
  }
});

app.post("/api/rooms/:key/files", async (req, res) => {
  try {
    const { key } = req.params;
    const { uploader, files } = req.body;
    const room = await Room.findOne({ key });
    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }
    files.forEach((file) => {
      room.files.push({
        uploader,
        name: file.name,
        url: file.url,
        size: file.size,
        code: file.code || Math.floor(100000 + Math.random() * 900000).toString(),
      });
    });
    await room.save();
    res.json({ message: "Files added to room", room });
  } catch (error) {
    res.status(500).json({ error: "Failed to add files to room" });
  }
});

app.get("/api/rooms", async (req, res) => {
  try {
    const rooms = await Room.find().sort({ createdAt: -1 });
    res.json(rooms);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch rooms" });
  }
});

app.delete("/api/rooms/:key/files/:filename", async (req, res) => {
  try {
    const { key, filename } = req.params;
    const room = await Room.findOne({ key });
    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }
    room.files = room.files.filter((f) => f.name !== filename);
    await room.save();
    res.json({ message: "File deleted from room" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete file from room" });
  }
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
