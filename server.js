import React, { useState } from "react";

const API_BASE = "https://filehub-gyll.onrender.com"; // ✅ Live backend

export default function Room() {
  const [room, setRoom] = useState(null);
  const [password, setPassword] = useState("");
  const [entered, setEntered] = useState(false);
  const [isCreating, setIsCreating] = useState(false);

  const [uploader, setUploader] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);

  // === Open existing room ===
  const handleEnterRoom = async () => {
    if (!password) {
      return alert("Enter room password");
    }
    try {
      const res = await fetch(`${API_BASE}/api/rooms/open`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }), // ✅ Only password
      });
      const data = await res.json();
      if (res.ok) {
        setRoom(data.room);
        setEntered(true);
      } else {
        alert(data.error || "Failed to open room");
      }
    } catch (err) {
      console.error("Open room error:", err);
      alert("Server error opening room");
    }
  };

  // === Create new room ===
  const handleCreateRoom = async () => {
    if (!password) {
      return alert("Enter a password for the room");
    }
    try {
      const res = await fetch(`${API_BASE}/api/rooms/create`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }), // ✅ Only password
      });
      const data = await res.json();
      if (res.ok) {
        setRoom(data);
        setEntered(true);
      } else {
        alert(data.error || "Failed to create room");
      }
    } catch (err) {
      console.error("Create room error:", err);
      alert("Server error creating room");
    }
  };

  // === Upload file to room ===
  const handleFileUpload = async () => {
    if (!selectedFile || !uploader) {
      return alert("Enter your name and select a file first");
    }

    const fileCode = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code

    try {
      const res = await fetch(`${API_BASE}/api/rooms/upload`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          roomPassword: password,
          name: uploader,
          code: fileCode,
          size: selectedFile.size,
          files: [
            {
              name: selectedFile.name,
              url: URL.createObjectURL(selectedFile),
            },
          ],
        }),
      });
      const data = await res.json();
      if (res.ok) {
        setRoom({ ...room, files: [...(room.files || []), data] });
        setSelectedFile(null);
      } else {
        alert(data.error || "Failed to upload file");
      }
    } catch (err) {
      console.error("Upload error:", err);
      alert("Server error uploading file");
    }
  };

  // === Login screen ===
  if (!entered) {
    return (
      <div className="flex justify-center items-center h-screen bg-black text-white">
        <div className="bg-[#111] p-6 rounded-lg shadow-lg w-96 text-center">
          <h2 className="text-xl font-bold text-fuchsia-400 mb-4">
            {isCreating ? "Create a Room" : "Open a Room"}
          </h2>

          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter Room Password"
            className="w-full px-3 py-2 rounded-md bg-gray-900 border border-gray-700 mb-4"
          />

          <button
            onClick={isCreating ? handleCreateRoom : handleEnterRoom}
            className="w-full py-2 bg-fuchsia-600 hover:bg-fuchsia-700 rounded-md text-white font-semibold"
          >
            {isCreating ? "Create Room" : "Enter Room"}
          </button>

          <p
            onClick={() => setIsCreating(!isCreating)}
            className="mt-4 text-sm text-fuchsia-400 cursor-pointer hover:underline"
          >
            {isCreating
              ? "Already have a room? Open it"
              : "Need a new room? Create one"}
          </p>
        </div>
      </div>
    );
  }

  // === Room Dashboard ===
  return (
    <div className="min-h-screen bg-black text-white p-6 font-[Orbitron]">
      <h1 className="text-3xl font-bold text-fuchsia-400 mb-6">
        Room Dashboard – Password: {password}
      </h1>

      {/* Upload Section */}
      <div className="flex gap-4 mb-6">
        <input
          type="text"
          placeholder="Your Name"
          value={uploader}
          onChange={(e) => setUploader(e.target.value)}
          className="px-3 py-2 rounded-md bg-gray-900 border border-gray-700"
        />
        <input
          type="file"
          onChange={(e) => setSelectedFile(e.target.files[0])}
          className="px-3 py-2 bg-gray-900 border border-gray-700"
        />
        <button
          onClick={handleFileUpload}
          className="px-4 py-2 bg-fuchsia-600 hover:bg-fuchsia-700 rounded-md"
        >
          Upload
        </button>
      </div>

      {/* Files Section */}
      <h2 className="text-xl font-bold mb-4">Files</h2>
      <div className="space-y-4">
        {!room.files || room.files.length === 0 ? (
          <p className="text-gray-400">No files uploaded yet.</p>
        ) : (
          room.files.map((file) => (
            <div
              key={file.code}
              className="bg-[#1b1b1b] p-4 rounded-md flex justify-between items-center"
            >
              <div>
                <p>
                  <span className="text-fuchsia-400 font-bold">Code:</span>{" "}
                  {file.code}
                </p>
                <p>
                  <span className="font-semibold">Name:</span>{" "}
                  <span className="text-blue-400">{file.name}</span>
                </p>
                <p className="text-sm text-gray-400">
                  {file.uploadedBy} – {(file.size / 1024).toFixed(1)} KB –{" "}
                  {new Date(file.date).toLocaleString()}
                </p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => window.open(file.url, "_blank")}
                  className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded-md text-xs"
                >
                  View
                </button>
                <a
                  href={file.url}
                  download={file.name}
                  className="px-3 py-1 bg-green-600 hover:bg-green-700 rounded-md text-xs"
                >
                  Download
                </a>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
