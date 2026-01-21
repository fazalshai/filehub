const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
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

// ===== CONNECT TO MONGODB =====
mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB Atlas"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ===== SCHEMA =====
// Shared File Schema
const fileSchema = new mongoose.Schema({
  name: String,
  url: String,
  size: Number,
  date: { type: Date, default: Date.now },
  type: String,
  code: String // ✅ Added code field
}, { _id: false });

const uploadSchema = new mongoose.Schema({
  name: String,
  files: [fileSchema],
  code: String,
  size: Number,
  date: { type: Date, default: Date.now },
});

const Upload = mongoose.model("Upload", uploadSchema);

// Workspace Schema
const workspaceSchema = new mongoose.Schema({
  boxName: { type: String, unique: true, required: true },
  pin: { type: String, required: true },
  files: [fileSchema],
  createdAt: { type: Date, default: Date.now }
});

const Workspace = mongoose.model("Workspace", workspaceSchema);

// ===== ROUTES =====

// Create new upload
app.post("/api/uploads", async (req, res) => {
  try {
    const { name, code, files, size } = req.body;
    if (!files || files.length === 0) return res.status(400).json({ error: "No files provided" });

    // Ensure anonymous files also match schema structure if needed, 
    // but the main "code" is on the parent Upload object for anonymous. 
    // We can leave anonymous files as is, or add the parent code to them too for consistency.
    // For now, let's just save.
    const newUpload = new Upload({ name, code, files, size });
    await newUpload.save();

    res.status(201).json({ message: "Upload metadata saved", code });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Failed to save upload metadata" });
  }
});

// Get a single upload by code (Search Logic)
app.get("/api/uploads/:code", async (req, res) => {
  try {
    const code = req.params.code;

    // 1. Check Anonymous Uploads (Parent Object has code)
    const uploadData = await Upload.findOne({ code });
    if (uploadData) {
      return res.json(uploadData);
    }

    // 2. Check Workspace Files (Child Object has code)
    // We need to find the workspace that contains a file with this code
    const workspace = await Workspace.findOne({ "files.code": code });
    if (workspace) {
      // Find the specific file
      const foundFile = workspace.files.find(f => f.code === code);
      // Return in a format the frontend Search.js expects
      // Search.js expects: { name: "Uploader Name", files: [ {name, url} ] }
      return res.json({
        name: "Shared File", // Masking the Box Name for privacy
        files: [foundFile]
      });
    }

    return res.status(404).json({ message: "No file found for this code" });
  } catch (error) {
    console.error("Search error:", error);
    res.status(500).json({ error: "Error fetching file" });
  }
});

// Get all uploads (admin use)
app.get("/api/uploads", async (req, res) => {
  try {
    const uploads = await Upload.find().sort({ date: -1 });
    res.json(uploads);
  } catch (err) {
    console.error("Admin fetch error:", err);
    res.status(500).json({ error: "Failed to fetch uploads" });
  }
});

// ===== NEW: DELETE upload by code (for main admin) =====
app.delete("/api/uploads/:code", async (req, res) => {
  try {
    const deleted = await Upload.findOneAndDelete({ code: req.params.code });
    if (!deleted) {
      return res.status(404).json({ message: "No upload found with this code" });
    }
    res.status(200).json({ message: "Upload deleted successfully" });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ error: "Error deleting upload" });
  }
});

// ===== WORKSPACE ROUTES =====

// 1. Create New Box
app.post("/api/box/create", async (req, res) => {
  try {
    const { boxName, pin } = req.body;

    // Check if box exists
    const existing = await Workspace.findOne({ boxName });
    if (existing) {
      return res.status(409).json({ error: "Box name already taken" });
    }

    const newBox = new Workspace({ boxName, pin, files: [] });
    await newBox.save();

    res.status(201).json({ message: "Box created successfully", boxName });
  } catch (error) {
    console.error("Create Box Error:", error);
    res.status(500).json({ error: "Failed to create box" });
  }
});

// 2. Login to Box
app.post("/api/box/login", async (req, res) => {
  try {
    const { boxName, pin } = req.body;
    const box = await Workspace.findOne({ boxName });

    if (!box) {
      return res.status(404).json({ error: "Box not found" });
    }
    if (box.pin !== pin) {
      return res.status(401).json({ error: "Incorrect PIN" });
    }

    // Return box details (excluding PIN ideally, but user asked for it in admin)
    // For login, we just return success and maybe the file list
    res.json({ message: "Login successful", boxName: box.boxName, files: box.files });
  } catch (error) {
    console.error("Login Error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// 3. Upload to Box
app.post("/api/workspaces/upload", async (req, res) => {
  try {
    const { boxName, pin, files } = req.body; // pin required for security
    const box = await Workspace.findOne({ boxName });

    if (!box) {
      return res.status(404).json({ error: "Box not found" });
    }
    if (box.pin !== pin) {
      return res.status(401).json({ error: "Unauthorized: Invalid PIN" });
    }

    // Add new files AND generate unique code for each
    const filesWithCodes = files.map(f => ({
      ...f,
      code: Math.floor(100000 + Math.random() * 900000).toString()
    }));

    box.files.push(...filesWithCodes);
    await box.save();

    res.json({ message: "Files added to box", files: box.files });
  } catch (error) {
    console.error("Box Upload Error:", error);
    res.status(500).json({ error: "Failed to save to box" });
  }
});

// 4. Get Box Files (Refetch)
app.get("/api/workspaces/:boxName", async (req, res) => {
  try {
    const { boxName } = req.params;
    const { pin } = req.query; // Pass PIN as query param for simple verification or use POST 

    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Box not found" });

    // Simple security
    if (pin && box.pin !== pin) {
      return res.status(401).json({ error: "Invalid PIN" });
    }

    res.json(box);
  } catch (error) {
    res.status(500).json({ error: "Fetch error" });
  }
});

// 5. Admin: Get ALL Workspaces
app.get("/api/admin/workspaces", async (req, res) => {
  try {
    const workspaces = await Workspace.find().sort({ createdAt: -1 });
    res.json(workspaces);
  } catch (error) {
    res.status(500).json({ error: "Admin fetch error" });
  }
});

// 6. Admin: Delete Workspace
app.delete("/api/admin/workspaces/:boxName", async (req, res) => {
  try {
    const deleted = await Workspace.findOneAndDelete({ boxName: req.params.boxName });
    if (!deleted) return res.status(404).json({ error: "Box not found" });
    res.json({ message: "Box deleted" });
  } catch (error) {
    res.status(500).json({ error: "Delete error" });
  }
});

// 7. Workspace: Delete File from Box
app.delete("/api/workspaces/:boxName/files/:code", async (req, res) => {
  try {
    const { boxName, code } = req.params;
    const { pin } = req.body; // Ideally pass PIN in body for security, or rely on trusted frontend

    // Find the workspace
    const box = await Workspace.findOne({ boxName });
    if (!box) return res.status(404).json({ error: "Box not found" });

    // Check if file exists
    const fileIndex = box.files.findIndex(f => f.code === code);
    if (fileIndex === -1) return res.status(404).json({ error: "File not found" });

    // Remove file
    box.files.splice(fileIndex, 1);
    await box.save();

    res.json({ message: "File deleted", files: box.files });
  } catch (error) {
    console.error("Delete File Error:", error);
    res.status(500).json({ error: "Failed to delete file" });
  }
});

// ===== START SERVER =====
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
