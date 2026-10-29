/** Minimal, safe CSV helpers (no URLs are ever fetched). */
export const MAX_BATCH = 100;

export function parseUrlList(text: string): string[] {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return [];
  // A header row naming a url/link column tells us which column to read.
  const first = splitCsvLine(lines[0]);
  const headerCol = first.findIndex((c) => /^(url|urls|link|website)$/i.test(c.trim()));
  const body = headerCol >= 0 ? lines.slice(1) : lines;
  const urls: string[] = [];
  for (const line of body) {
    const cells = splitCsvLine(line);
    const cell = headerCol >= 0 ? cells[headerCol] : cells.length > 1 ? cells.find((c) => /^https?:\/\//i.test(c)) ?? cells[0] : cells[0];
    if (cell) urls.push(cell);
  }
  return urls;
}

function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ",") { out.push(cur.trim()); cur = ""; }
    else cur += ch;
  }
  out.push(cur.trim());
  return out;
}

export function csvEscape(v: string | number | null): string {
  const s = v == null ? "" : String(v);
  const guarded = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s; // neutralise spreadsheet formula injection
  return /[",\n]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
}

export function toCsv(rows: (string | number | null)[][]): string {
  return rows.map((r) => r.map(csvEscape).join(",")).join("\n");
}
