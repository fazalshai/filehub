const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5001;
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

// Serve uploads statically so files are accessible
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ===== MULTER CONFIG =====
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    // Keep original name but prepend timestamp to avoid collisions
    cb(null, Date.now() + "-" + file.originalname);
  }
});
const upload = multer({ storage });

// ===== CONNECT TO MONGODB =====
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ===== SCHEMA =====
const fileSchema = new mongoose.Schema({
  name: String,
  url: String, // Will now be a relative path or full URL to server
  size: Number,
  date: { type: Date, default: Date.now },
  type: String,
  code: String
}, { _id: false });

const uploadSchema = new mongoose.Schema({
  name: String,
  files: [fileSchema],
  code: String,
  size: Number,
  date: { type: Date, default: Date.now },
});

const Upload = mongoose.model("Upload", uploadSchema);

const workspaceSchema = new mongoose.Schema({
  boxName: { type: String, unique: true, required: true },
  pin: { type: String, required: true },
  files: [fileSchema],
  createdAt: { type: Date, default: Date.now }
});

const Workspace = mongoose.model("Workspace", workspaceSchema);

// ===== ROUTES =====

// Create new upload (Multipart/Form-Data)
app.post("/api/uploads", upload.array("files"), async (req, res) => {
  try {
    const { name, code, size } = req.body;

    // Process uploaded files
    const fileData = req.files.map(file => ({
      name: file.originalname,
      // Construct URL: server_origin/uploads/filename
      url: `${req.protocol}://${req.get("host")}/uploads/${file.filename}`,
      size: file.size,
      type: file.mimetype,
      code: code // Linking file to the upload session code
    }));

    if (fileData.length === 0) return res.status(400).json({ error: "No files provided" });

    const newUpload = new Upload({ name, code, files: fileData, size });
    await newUpload.save();

    res.status(201).json({ message: "Upload successful", code, files: fileData });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Failed to save upload" });
  }
});

// Get a single upload by code
app.get("/api/uploads/:code", async (req, res) => {
  try {
    const code = req.params.code;
    const uploadData = await Upload.findOne({ code });
    if (uploadData) {
      return res.json(uploadData);
    }

    const workspace = await Workspace.findOne({ "files.code": code });
    if (workspace) {
      const foundFile = workspace.files.find(f => f.code === code);
      return res.json({
        name: "Shared File",
        files: [foundFile]
      });
    }

    return res.status(404).json({ message: "No file found for this code" });
  } catch (error) {
    console.error("Search error:", error);
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
    const upload = await Upload.findOneAndDelete({ code: req.params.code });
    if (!upload) return res.status(404).json({ message: "No upload found" });

    // Optional: Delete physical files from disk
    // upload.files.forEach(f => { ... fs.unlink ... })

    res.status(200).json({ message: "Upload deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error deleting upload" });
  }
});

// ===== WORKSPACE ROUTES =====

app.post("/api/box/create", async (req, res) => {
  try {
    const { boxName, pin } = req.body;
    const existing = await Workspace.findOne({ boxName });
    if (existing) return res.status(409).json({ error: "Box name already taken" });

    const newBox = new Workspace({ boxName, pin, files: [] });
    await newBox.save();
    res.status(201).json({ message: "Box created successfully", boxName });
  } catch (error) {
    res.status(500).json({ error: "Failed to create box" });
  }
});

app.post("/api/box/login", async (req, res) => {
  try {
    const { boxName, pin } = req.body;
    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Box not found" });
    if (box.pin !== pin) return res.status(401).json({ error: "Incorrect PIN" });

    res.json({ message: "Login successful", boxName: box.boxName, files: box.files });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Upload to Box (Multipart/Form-Data)
app.post("/api/workspaces/upload", upload.array("files"), async (req, res) => {
  try {
    const { boxName, pin } = req.body;
    const box = await Workspace.findOne({ boxName });

    if (!box) return res.status(404).json({ error: "Box not found" });
    if (box.pin !== pin) return res.status(401).json({ error: "Unauthorized: Invalid PIN" });

    const newFiles = req.files.map(file => ({
      name: file.originalname,
      url: `${req.protocol}://${req.get("host")}/uploads/${file.filename}`,
      size: file.size,
      type: file.mimetype,
      code: Math.floor(100000 + Math.random() * 900000).toString()
    }));

    box.files.push(...newFiles);
    await box.save();

    res.json({ message: "Files added to box", files: box.files });
  } catch (error) {
    console.error("Box Upload Error:", error);
    res.status(500).json({ error: "Failed to save to box" });
  }
});

app.get("/api/workspaces/:boxName", async (req, res) => {
  try {
    const { boxName } = req.params;
    const { pin } = req.query;

    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Box not found" });
    if (pin && box.pin !== pin) return res.status(401).json({ error: "Invalid PIN" });

    res.json(box);
  } catch (error) {
    res.status(500).json({ error: "Fetch error" });
  }
});

app.get("/api/admin/workspaces", async (req, res) => {
  try {
    const workspaces = await Workspace.find().sort({ createdAt: -1 });
    res.json(workspaces);
  } catch (error) {
    res.status(500).json({ error: "Admin fetch error" });
  }
});

app.delete("/api/admin/workspaces/:boxName", async (req, res) => {
  try {
    const deleted = await Workspace.findOneAndDelete({ boxName: req.params.boxName });
    if (!deleted) return res.status(404).json({ error: "Box not found" });
    res.json({ message: "Box deleted" });
  } catch (error) {
    res.status(500).json({ error: "Delete error" });
  }
});

app.delete("/api/workspaces/:boxName/files/:code", async (req, res) => {
  try {
    const { boxName, code } = req.params;
    const { pin } = req.body;

    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Box not found" });

    const fileIndex = box.files.findIndex(f => f.code === code);
    if (fileIndex === -1) return res.status(404).json({ error: "File not found" });

    // Optional: Delete physical file
    // const fileToDelete = box.files[fileIndex];
    // fs.unlink(...)

    box.files.splice(fileIndex, 1);
    await box.save();

    res.json({ message: "File deleted", files: box.files });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete file" });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
