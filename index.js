import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORDS_PATH = path.join(__dirname, "words.json");

const app = express();
app.use(cors());
app.use(express.json());

function readWords() {
  const raw = fs.readFileSync(WORDS_PATH, "utf8");
  const data = JSON.parse(raw);
  return data.words || [];
}

function writeWords(words) {
  fs.writeFileSync(WORDS_PATH, JSON.stringify({ words }, null, 2), "utf8");
}

app.get("/words", (req, res) => {
  try {
    const words = readWords();
    res.json({ words });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to read words" });
  }
});

app.post("/words", (req, res) => {
  try {
    const { accent, stress_index } = req.body;
    if (typeof accent !== "string" || typeof stress_index !== "number") {
      return res.status(400).json({ error: "Need accent (string) and stress_index (number)" });
    }
    const words = readWords();
    words.push({ accent: accent.trim().toLowerCase(), stress_index });
    writeWords(words);
    res.status(201).json({ words });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to add word" });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
