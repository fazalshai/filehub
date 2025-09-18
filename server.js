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
  files: [{ name: String, url: String }],
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
      code: String,
      name: String,
      url: String,
      size: Number,
      uploadedAt: { type: Date, default: Date.now },
    },
  ],
  createdAt: { type: Date, default: Date.now },
});
const Room = mongoose.model("Room", roomSchema);

// ===== ROUTES =====
app.post("/api/rooms/create", async (req, res) => {
  try {
    const { name, key } = req.body;
    const existing = await Room.findOne({ key });
    if (existing) return res.status(400).json({ error: "Room key already exists" });

    const newRoom = new Room({ name, key, files: [] });
    await newRoom.save();
    res.status(201).json({ message: "Room created", room: newRoom });
  } catch (err) {
    res.status(500).json({ error: "Failed to create room" });
  }
});

app.post("/api/rooms/open", async (req, res) => {
  try {
    const { key } = req.body;
    const room = await Room.findOne({ key });
    if (!room) return res.status(404).json({ error: "Room not found" });
    res.status(200).json({ message: "Room opened", room });
  } catch (err) {
    res.status(500).json({ error: "Failed to open room" });
  }
});

app.post("/api/rooms/:key/upload", async (req, res) => {
  try {
    const { key } = req.params;
    const { uploader, files, size } = req.body;

    const room = await Room.findOne({ key });
    if (!room) return res.status(404).json({ error: "Room not found" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();

    const newUpload = new Upload({ name: uploader, code, files, size });
    await newUpload.save();

    room.files.push({
      code,
      name: files[0].name,
      url: files[0].url,
      size,
    });
    await room.save();

    res.status(201).json({ message: "File uploaded to room", room, code });
  } catch (err) {
    res.status(500).json({ error: "Failed to upload file to room" });
  }
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
