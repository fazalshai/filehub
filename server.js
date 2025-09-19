// server.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

// In-memory storage (replace with DB later if needed)
let generalUploads = [];
let roomUploads = [];

/**
 * ===============================
 * Uploads (General)
 * ===============================
 */
app.post("/api/uploads", (req, res) => {
  try {
    const { name, files, code, size } = req.body;
    if (!name || !files || files.length === 0 || !code) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const sizeMB = (size / 1024 / 1024).toFixed(2);

    const uploadEntry = {
      code,
      name,
      files,
      size: sizeMB,
      uploadedBy: name,
      date: new Date(),
      type: "general",
    };

    generalUploads.push(uploadEntry);
    res.json(uploadEntry);
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * ===============================
 * Room Uploads
 * ===============================
 */
app.post("/api/rooms/upload", (req, res) => {
  try {
    const { roomCode, name, files, code, size } = req.body;
    if (!roomCode || !name || !files || files.length === 0 || !code) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const sizeMB = (size / 1024 / 1024).toFixed(2);

    const roomEntry = {
      roomCode,
      code,
      name,
      files,
      size: sizeMB,
      uploadedBy: name,
      date: new Date(),
      type: "room",
    };

    roomUploads.push(roomEntry);
    res.json(roomEntry);
  } catch (err) {
    console.error("Room upload error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/**
 * ===============================
 * GET Upload by Code (for Search)
 * ===============================
 */
app.get("/api/uploads/:code", (req, res) => {
  const { code } = req.params;
  const allUploads = [...generalUploads, ...roomUploads];
  const found = allUploads.find((u) => u.code === code);

  if (!found) {
    return res.status(404).json({ error: "No file found for this code" });
  }
  res.json(found);
});

/**
 * ===============================
 * GET All Uploads (for Admin)
 * ===============================
 */
app.get("/api/uploads", (req, res) => {
  const allUploads = [...generalUploads, ...roomUploads];
  // Sort newest first
  allUploads.sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json(allUploads);
});

/**
 * ===============================
 * DELETE Upload by Code
 * ===============================
 */
app.delete("/api/uploads/:code", (req, res) => {
  const { code } = req.params;
  const beforeCount = generalUploads.length + roomUploads.length;

  generalUploads = generalUploads.filter((u) => u.code !== code);
  roomUploads = roomUploads.filter((u) => u.code !== code);

  const afterCount = generalUploads.length + roomUploads.length;

  if (afterCount === beforeCount) {
    return res.status(404).json({ error: "Upload not found" });
  }

  res.json({ success: true, code });
});

/**
 * ===============================
 * GET Room Uploads (for Room.js)
 * ===============================
 */
app.get("/api/rooms/:roomCode", (req, res) => {
  const { roomCode } = req.params;
  const files = roomUploads.filter((u) => u.roomCode === roomCode);
  res.json(files);
});

/**
 * ===============================
 * Server Start
 * ===============================
 */
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
