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

// ===== SCHEMAS =====

// General Upload Schema (no password)
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

// Room Schema (password-protected uploads)
const roomSchema = new mongoose.Schema({
  name: String, // room creator
  key: { type: String, unique: true, required: true }, // password
  files: [
    {
      uploader: String,
      name: String,
      url: String,
      size: Number,
      date: { type: Date, default: Date.now }
    }
  ],
  createdAt: { type: Date, default: Date.now },
});
const Room = mongoose.model("Room", roomSchema);

// ==================== ROUTES ====================

// -------- General Upload Routes --------
app.post("/api/uploads", async (req, res) => {
  try {
    const { name, code, files, size } = req.body;
    if (!files || files.length === 0) {
      return res.status(400).json({ error: "No files provided" });
    }

    const newUpload = new Upload({ name, code, files, size });
    await newUpload.save();

    res.status(201).json({ message: "Upload saved", code });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Failed to save upload" });
  }
});

app.get("/api/uploads/:code", async (req, res) => {
  try {
    const data = await Upload.findOne({ code: req.params.code });
    if (!data) return res.status(404).json({ message: "No file found" });
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: "Error fetching file" });
  }
});

app.get("/api/uploads", async (req, res) => {
  try {
    const uploads = await Upload.find().sort({ date: -1 });
    res.json(uploads);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch uploads" });
  }
});

app.delete("/api/uploads/:code", async (req, res) => {
  try {
    const deleted = await Upload.findOneAndDelete({ code: req.params.code });
    if (!deleted) return res.status(404).json({ message: "Not found" });
    res.json({ message: "Deleted" });
  } catch (error) {
    res.status(500).json({ error: "Error deleting upload" });
  }
});

// -------- Room Routes --------

// Create new Room
app.post("/api/rooms/create", async (req, res) => {
  try {
    const { name, key } = req.body;

    const existing = await Room.findOne({ key });
    if (existing) {
      return res.status(400).json({ error: "Room password already exists" });
    }

    const newRoom = new Room({ name, key, files: [] });
    await newRoom.save();

    res.status(201).json({ message: "Room created", room: newRoom });
  } catch (error) {
    res.status(500).json({ error: "Failed to create room" });
  }
});

// Open Room by password
app.post("/api/rooms/open", async (req, res) => {
  try {
    const { key } = req.body;
    const room = await Room.findOne({ key });
    if (!room) return res.status(404).json({ error: "Room not found" });
    res.json({ message: "Room opened", room });
  } catch (error) {
    res.status(500).json({ error: "Failed to open room" });
  }
});

// Upload files into Room
app.post("/api/rooms/upload", async (req, res) => {
  try {
    const { key, uploader, files } = req.body;
    if (!files || files.length === 0) {
      return res.status(400).json({ error: "No files provided" });
    }

    const room = await Room.findOne({ key });
    if (!room) return res.status(404).json({ error: "Room not found" });

    files.forEach(f => {
      room.files.push({
        uploader,
        name: f.name,
        url: f.url,
        size: f.size || 0,
        date: new Date()
      });
    });

    await room.save();
    res.json({ message: "Files uploaded to room", room });
  } catch (error) {
    res.status(500).json({ error: "Failed to upload files to room" });
  }
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
