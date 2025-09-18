import React, { useState } from "react";

export default function Room() {
  const [tab, setTab] = useState("open");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [room, setRoom] = useState(null);
  const [files, setFiles] = useState([]);
  const [error, setError] = useState("");
  const [uploading, setUploading] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  // ===== Create Room =====
  const handleCreateRoom = async () => {
    try {
      const res = await fetch("https://filehub-gyll.onrender.com/api/rooms/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, key: password }),
      });

      const data = await res.json();
      if (res.ok) {
        setRoom(data.room);
        setFiles(data.room.files || []);
        setError("");
      } else {
        setError(data.error || "Failed to create room");
      }
    } catch {
      setError("Server error while creating room");
    }
  };

  // ===== Open Room =====
  const handleOpenRoom = async () => {
    try {
      const res = await fetch("https://filehub-gyll.onrender.com/api/rooms/open", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: password }),
      });

      const data = await res.json();
      if (res.ok) {
        setRoom(data.room);
        setFiles(data.room.files || []);
        setError("");
      } else {
        setError(data.error || "Invalid password");
      }
    } catch {
      setError("Server error while opening room");
    }
  };

  // ===== Upload to Room =====
  const handleFileUpload = async () => {
    if (!selectedFile) return;

    setUploading(true);
    try {
      const fileMeta = {
        name: selectedFile.name,
        url: URL.createObjectURL(selectedFile), // (for real app, upload to Firebase/S3 then save URL)
      };

      const res = await fetch(`https://filehub-gyll.onrender.com/api/rooms/${room.key}/upload`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          uploader: name || "Anonymous",
          files: [fileMeta],
          size: selectedFile.size / (1024 * 1024), // MB
        }),
      });

      const data = await res.json();
      if (res.ok) {
        setFiles(data.room.files || []);
        setError("");
      } else {
        setError(data.error || "Failed to upload file");
      }
    } catch {
      setError("Server error while uploading");
    } finally {
      setUploading(false);
    }
  };

  // ===== Login/Create UI =====
  if (!room) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-black text-white font-[Orbitron]">
        <div className="bg-[#0f172a] p-8 rounded-lg shadow-lg w-96">
          <div className="flex justify-center mb-4 space-x-4">
            <button
              onClick={() => setTab("open")}
              className={`px-4 py-2 rounded ${tab === "open" ? "bg-fuchsia-600" : "bg-gray-700"}`}
            >
              Open Room
            </button>
            <button
              onClick={() => setTab("create")}
              className={`px-4 py-2 rounded ${tab === "create" ? "bg-fuchsia-600" : "bg-gray-700"}`}
            >
              Create Room
            </button>
          </div>

          <h2 className="text-2xl font-bold text-fuchsia-400 mb-4 text-center">
            {tab === "open" ? "Open a Room" : "Create a Room"}
          </h2>

          {tab === "create" && (
            <input
              type="text"
              placeholder="Your Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full p-2 mb-3 rounded bg-[#1e293b] text-white"
            />
          )}

          <input
            type="password"
            placeholder="Room Password (Key)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full p-2 mb-4 rounded bg-[#1e293b] text-white"
          />

          <button
            onClick={tab === "open" ? handleOpenRoom : handleCreateRoom}
            className="w-full bg-fuchsia-600 hover:bg-fuchsia-700 text-white py-2 rounded font-bold"
          >
            {tab === "open" ? "Enter Room" : "Create Room"}
          </button>

          {error && <p className="text-red-400 text-sm mt-3">{error}</p>}
        </div>
      </div>
    );
  }

  // ===== Room Dashboard =====
  return (
    <div className="min-h-screen bg-black text-white font-[Orbitron] p-8">
      <h1 className="text-3xl font-bold text-fuchsia-400 mb-6">
        Room Dashboard – {room.key}
      </h1>

      {room.name && <p className="mb-4 text-gray-300">Welcome, {room.name} 👋</p>}

      {/* Upload Section */}
      <div className="mb-6">
        <input
          type="file"
          onChange={(e) => setSelectedFile(e.target.files[0])}
          className="mb-3"
        />
        <button
          onClick={handleFileUpload}
          disabled={uploading}
          className="bg-green-600 hover:bg-green-700 px-4 py-2 rounded text-white font-bold"
        >
          {uploading ? "Uploading..." : "Upload File"}
        </button>
      </div>

      {/* File List */}
      <div className="bg-[#111827] p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-3">Uploaded Files</h2>
        {files.length === 0 ? (
          <p className="text-gray-400">No files uploaded yet.</p>
        ) : (
          <ul className="space-y-3">
            {files.map((file, i) => (
              <li key={i} className="flex justify-between items-center bg-[#1e293b] p-2 rounded">
                <div>
                  <p className="font-semibold">{file.name}</p>
                  <p className="text-sm text-gray-400">Code: {file.code}</p>
                </div>
                <div className="space-x-3">
                  <a href={file.url} target="_blank" rel="noopener noreferrer" className="text-blue-400">👁 View</a>
                  <a href={file.url} download className="text-green-400">⬇ Download</a>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
