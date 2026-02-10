import fs from "fs";

const INPUT = "./words.json";
const OUTPUT = "./words_consonant_stress.json";

const VOWELS = new Set(["а", "е", "ё", "и", "о", "у", "ы", "э", "ю", "я"]);

function isRussianLetter(ch) {
  return /[А-Яа-яЁё]/.test(ch);
}

function hasStressOnConsonant(accent, stressIndex) {
  if (typeof accent !== "string") return false;
  if (typeof stressIndex !== "number") return false;
  if (stressIndex < 0 || stressIndex >= accent.length) return false;

  const ch = accent[stressIndex];
  const lower = ch.toLowerCase();

  if (!isRussianLetter(lower)) return false;
  if (VOWELS.has(lower)) return false;
  if (lower === "ь" || lower === "ъ") return false;

  return true;
}

const raw = fs.readFileSync(INPUT, "utf8");
const data = JSON.parse(raw);
const words = data.words || [];

const filtered = words.filter((w) => hasStressOnConsonant(w.accent, w.stress_index));

fs.writeFileSync(
  OUTPUT,
  JSON.stringify({ words: filtered }, null, 2),
  "utf8"
);

console.log(`Total words: ${words.length}`);
console.log(`Words with stress on consonant: ${filtered.length}`);
console.log(`Saved to ${OUTPUT}`);

