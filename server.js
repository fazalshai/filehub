// server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
require("dotenv").config();

// -------------------------
// CONFIG
// -------------------------
const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017/fylshare";

// Allowed origins
const allowedOrigins = [
  "https://filehub-gyll.web.app",
  "https://fileverse-krwk3.web.app",
  "http://localhost:3000",
  "http://localhost:3002",
  "https://fylshare.com",
];

// CORS middleware
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use(bodyParser.json());

// -------------------------
// DB CONNECTION
// -------------------------
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// -------------------------
// SCHEMAS + MODELS
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
  roomCode: { type: String, default: null },
});

const RoomSchema = new mongoose.Schema({
  roomName: { type: String, required: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  files: [{ type: mongoose.Schema.Types.ObjectId, ref: "FileUpload" }],
});

const FileUpload = mongoose.model("FileUpload", FileSchema);
const Room = mongoose.model("Room", RoomSchema);

// -------------------------
// ROUTES
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
 * Create Room
 */
app.post("/api/rooms/create", async (req, res) => {
  try {
    const { roomName, password } = req.body;
    if (!roomName || !password) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const newRoom = new Room({ roomName, password });
    await newRoom.save();
    res.json(newRoom);
  } catch (err) {
    console.error("Room creation error:", err);
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

    // attach file to the room
    await Room.findByIdAndUpdate(roomCode, { $push: { files: roomEntry._id } });

    res.json(roomEntry);
  } catch (err) {
    console.error("Room upload error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * Get Upload by Code (Search)
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
 * Get All Uploads (Admin)
 */
app.get("/api/uploads", async (req, res) => {
  try {
    const general = await FileUpload.find({ type: "general" }).sort({ date: -1 });
    const rooms = await Room.find().populate("files").sort({ createdAt: -1 });

    res.json({ general, rooms });
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
 * Get Files of a Room
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
// START SERVER
// -------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
