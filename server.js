const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
require("dotenv").config();  // To load the environment variables

// -------------------------
// CONFIG
// -------------------------
const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://fazalshaik24434_db_user:iPxI9z2vzHFw4zpC@cluster0.brelwu6.mongodb.net/fylshare?retryWrites=true&w=majority"; // Replace with your Mongo URI

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
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// -------------------------
// SCHEMAS + MODELS
// -------------------------
const FileSchema = new mongoose.Schema({
  code: { type: String, required: true },
  name: { type: String, required: true },
  files: [{ name: String, url: String }],
  size: String,
  uploadedBy: String,
  date: { type: Date, default: Date.now },
  type: { type: String, enum: ["general", "room"], default: "general" },
  roomPassword: { type: String, default: null }, // 🔑 link to room by password
});

const RoomSchema = new mongoose.Schema({
  password: { type: String, required: true, unique: true }, // 🔑 unique room password
  createdAt: { type: Date, default: Date.now },
  files: [{ type: mongoose.Schema.Types.ObjectId, ref: "FileUpload" }],
});

const FileUpload = mongoose.model("FileUpload", FileSchema);
const Room = mongoose.model("Room", RoomSchema);

// -------------------------
// ROUTES
// -------------------------

// Uploads (General)
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

// Create Room (password only)
app.post("/api/rooms/create", async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ error: "Missing password" });
    }

    const existing = await Room.findOne({ password });
    if (existing) return res.status(400).json({ error: "Room already exists" });

    const newRoom = new Room({ password });
    await newRoom.save();
    res.json({ room: newRoom });
  } catch (err) {
    console.error("Room creation error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Open Room (by password)
app.post("/api/rooms/open", async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ error: "Missing password" });
    }

    const room = await Room.findOne({ password }).populate("files");
    if (!room) return res.status(404).json({ error: "Room not found" });

    res.json({ room });
  } catch (err) {
    console.error("Room open error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Room Uploads
app.post("/api/rooms/upload", async (req, res) => {
  try {
    const { roomPassword, name, files, code, size } = req.body;
    if (!roomPassword || !name || !files || files.length === 0 || !code) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const sizeMB = (size / 1024 / 1024).toFixed(2);

    const roomEntry = new FileUpload({
      roomPassword,
      code,
      name,
      files,
      size: sizeMB,
      uploadedBy: name,
      type: "room",
    });

    await roomEntry.save();

    await Room.findOneAndUpdate(
      { password: roomPassword },
      { $push: { files: roomEntry._id } },
      { new: true }
    );

    res.json(roomEntry);
  } catch (err) {
    console.error("Room upload error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Delete Entire Room
app.delete("/api/rooms/:password", async (req, res) => {
  try {
    const { password } = req.params;
    const room = await Room.findOne({ password });
    if (!room) return res.status(404).json({ error: "Room not found" });

    await FileUpload.deleteMany({ roomPassword: password });
    await Room.deleteOne({ password });

    res.json({ success: true, password });
  } catch (err) {
    console.error("Room delete error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// -------------------------
// START SERVER
// -------------------------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
