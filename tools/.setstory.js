// Replace a record's story block in place, preserving the file's block-scalar style and
// indentation. A yaml round-trip would reformat the whole file; this touches only the
// story. Input: a JSON file mapping "<path>::<attack id>" -> new story text.
const fs = require("fs"), yaml = require("js-yaml");

const edits = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
let done = 0;

for (const [key, text] of Object.entries(edits)) {
  const [file, id] = key.split("::");
  const original = fs.readFileSync(file, "utf8");
  const lines = original.split("\n");

  // Find the story block belonging to this record. The id key may sit before or after
  // the story, so anchor on the record only when the file holds more than one story.
  const idRe = new RegExp(`^ {0,2}(- )?id: ${id}\\s*$`);
  const storyRe = /^ {0,2}story: (\||>)-?\s*$/;
  const storyLines = lines.map((l, i) => (storyRe.test(l) ? i : -1)).filter(i => i >= 0);
  const hasId = lines.some(l => idRe.test(l));
  if (!hasId) { console.error(`record ${id} not found in ${file}`); continue; }
  let start = -1;
  if (storyLines.length === 1) {
    start = storyLines[0];
  } else {
    let idLine = -1;
    for (let i = 0; i < lines.length; i += 1) {
      if (idRe.test(lines[i])) idLine = i;
      if (idLine >= 0 && storyRe.test(lines[i])) { start = i; break; }
    }
    // The id may follow its own story, so fall back to the nearest story above it.
    if (start === -1 && idLine >= 0) {
      const above = storyLines.filter(i => i < idLine);
      if (above.length) start = above[above.length - 1];
    }
  }
  if (start === -1) { console.error(`no story block for ${id} in ${file}`); continue; }

  let end = start + 1;
  while (end < lines.length && (lines[end].startsWith("    ") || lines[end].trim() === "")) end += 1;
  while (end > start + 1 && lines[end - 1].trim() === "") end -= 1;

  const style = lines[start].includes("-") ? "|-" : "|";
  const body = text.trim().split("\n").map(l => (l.trim() ? `    ${l}` : "")).join("\n");
  const rebuilt = [...lines.slice(0, start), `  story: ${style}`, ...body.split("\n"), ...lines.slice(end)];
  const updated = rebuilt.join("\n");

  // Refuse to write anything that does not parse or that lost the paragraph budget.
  let parsed;
  try { parsed = yaml.load(updated); } catch (e) { console.error(`${id}: YAML would break: ${e.message}`); continue; }
  const rec = (Array.isArray(parsed) ? parsed : [parsed]).find(r => r && r.id === id);
  const paras = String(rec.story).trim().split(/\n\s*\n/).filter(p => p.trim()).length;
  if (paras < 2 || paras > 4) { console.error(`${id}: ${paras} paragraphs, refusing`); continue; }

  fs.writeFileSync(file, updated);
  console.log(`${id}: ${paras} paragraphs`);
  done += 1;
}
console.log(`rewritten: ${done}/${Object.keys(edits).length}`);
