const mongoose = require("mongoose");
require("dotenv").config({ path: "./.env" });

const MONGO_URI = process.env.MONGO_URI;

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

const codesToCheck = ["735586", "878217", "778241", "247417"];

async function check() {
    try {
        await mongoose.connect(MONGO_URI);
        console.log("Connected to DB");

        const documents = await Upload.find({ code: { $in: codesToCheck } });

        // Also check workspaces if not found in Uploads?
        // The user said "those files", usually uploads.
        // server.js shows checking uploads then workspaces.

        // Let's just dump what we find.
        console.log(`Found ${documents.length} documents.`);

        documents.forEach(doc => {
            console.log(`Code: ${doc.code}`);
            doc.files.forEach(f => {
                console.log(` - File: ${f.name}`);
                console.log(` - URL: ${f.url}`);
            });
        });

    } catch (err) {
        console.error(err);
    } finally {
        await mongoose.disconnect();
    }
}

check();
