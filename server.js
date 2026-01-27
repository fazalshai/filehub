const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const admin = require("firebase-admin");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5001;
const MONGO_URI = process.env.MONGO_URI;

// ===== FIREBASE CONFIG =====
let serviceAccount;
try {
  if (process.env.FIREBASE_CREDENTIALS) {
    serviceAccount = JSON.parse(process.env.FIREBASE_CREDENTIALS);
  } else {
    serviceAccount = require("./serviceAccountKey.json");
  }
} catch (error) {
  console.error("Failed to load Firebase credentials:", error);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: "fileverse-krwk3.firebasestorage.app"
});

const bucket = admin.storage().bucket();

// ===== MIDDLEWARE =====
const allowedOrigins = [
  "https://filehub-gyll.web.app",
  "https://fileverse-krwk3.web.app",
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:3002",
  "https://fylshare.com",
  "https://www.fylshare.com",
  "https://fylshare.vercel.app"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(null, true); // Allow all for now to avoid CORS headaches during debug
      }
    }
  })
);

app.use(express.json());

// ===== MULTER CONFIG (MEMORY STORAGE) =====
// Store files in memory so we can upload to Firebase
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 1024 * 1024 * 1024 } // 1GB Limit
});

// ===== CONNECT TO MONGODB =====
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ===== SCHEMA =====
const fileSchema = new mongoose.Schema({
  name: String,
  url: String,
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

// ===== HELPER: UPLOAD TO FIREBASE =====
async function uploadToFirebase(file) {
  const fileName = `${Date.now()}-${file.originalname}`;
  const fileUpload = bucket.file(`uploads/${fileName}`);

  const stream = fileUpload.createWriteStream({
    metadata: {
      contentType: file.mimetype
    }
  });

  return new Promise((resolve, reject) => {
    stream.on("error", (err) => {
      reject(err);
    });

    stream.on("finish", async () => {
      // Make the file public
      await fileUpload.makePublic();
      const publicUrl = `https://storage.googleapis.com/${bucket.name}/uploads/${fileName}`;
      resolve({
        name: file.originalname,
        url: publicUrl,
        size: file.size,
        type: file.mimetype
      });
    });

    stream.end(file.buffer);
  });
}

// ===== ROUTES =====

// Create new upload (Multipart/Form-Data)
app.post("/api/uploads", upload.array("files"), async (req, res) => {
  try {
    const { name, code, size } = req.body;

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No files provided" });
    }

    // Upload all files to Firebase
    const uploadPromises = req.files.map(file => uploadToFirebase(file));
    const uploadedFiles = await Promise.all(uploadPromises);

    // Add code to each file object
    const finalFileData = uploadedFiles.map(f => ({ ...f, code }));

    const newUpload = new Upload({ name, code, files: finalFileData, size });
    await newUpload.save();

    res.status(201).json({ message: "Upload successful", code, files: finalFileData });
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

// DELETE
app.delete("/api/uploads/:code", async (req, res) => {
  try {
    const upload = await Upload.findOneAndDelete({ code: req.params.code });
    if (!upload) return res.status(404).json({ message: "No upload found" });
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

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No files provided" });
    }

    // Upload all files to Firebase
    const uploadPromises = req.files.map(file => uploadToFirebase(file));
    const uploadedFiles = await Promise.all(uploadPromises);

    const newFiles = uploadedFiles.map(f => ({
      ...f,
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
    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Box not found" });

    const fileIndex = box.files.findIndex(f => f.code === code);
    if (fileIndex === -1) return res.status(404).json({ error: "File not found" });

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

