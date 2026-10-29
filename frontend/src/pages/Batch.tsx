import { useMutation } from "@tanstack/react-query";
import { ArrowDown, ArrowUp, Download, Loader2, Upload } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { Badge, Card, Notice, PageHeader } from "../components/common/ui";
import { EmptyState, ErrorState } from "../components/feedback/states";
import { api } from "../services/api";
import type { BatchItem } from "../types/api";
import { MAX_BATCH, parseUrlList, toCsv } from "../utils/csv";
import { pct } from "../utils/format";

type Filter = "all" | "phishing" | "legitimate" | "invalid";
type SortKey = "index" | "score" | "label" | "status";
const MAX_FILE_BYTES = 1_000_000;

function readText(f: File): Promise<string> {
  if (typeof f.text === "function") return f.text();
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result ?? ""));
    r.onerror = () => reject(r.error);
    r.readAsText(f);
  });
}

export function BatchPage() {
  const [text, setText] = useState("");
  const [urls, setUrls] = useState<string[]>([]);
  const [inputError, setInputError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "index", dir: 1 });
  const fileRef = useRef<HTMLInputElement>(null);

  const m = useMutation({ mutationFn: (u: string[]) => api.predictBatch(u) });

  const prepare = (raw: string): string[] | null => {
    const list = parseUrlList(raw);
    if (list.length === 0) { setInputError("No URLs found. Enter one URL per line, or upload a CSV/TXT file with a URL column."); return null; }
    if (list.length > MAX_BATCH) { setInputError(`Batches are limited to ${MAX_BATCH} URLs (you entered ${list.length}). Split the list and run it in parts.`); return null; }
    setInputError(null);
    return list;
  };

  const run = () => {
    const list = prepare(text);
    if (!list) return;
    setUrls(list);
    m.mutate(list);
  };

  const onFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > MAX_FILE_BYTES) { setInputError("That file is larger than 1 MB. Upload a smaller CSV or TXT file."); return; }
    if (!/\.(csv|txt)$/i.test(f.name) && !/^text\//.test(f.type)) { setInputError("Unsupported file type. Upload a .csv or .txt file."); return; }
    try {
      const content = await readText(f);
      setText(content);
      const list = parseUrlList(content);
      if (list.length === 0) setInputError("The file contains no URLs.");
      else if (list.length > MAX_BATCH) setInputError(`The file has ${list.length} URLs; batches are limited to ${MAX_BATCH}.`);
      else setInputError(null);
    } catch {
      setInputError("The file could not be read.");
    }
    if (fileRef.current) fileRef.current.value = "";
  };

  const rows = useMemo(() => {
    const data = m.data?.results ?? [];
    const pass = (r: BatchItem) => filter === "all" || (filter === "invalid" ? r.status === "invalid" : r.class_name === filter);
    const val = (r: BatchItem) => sort.key === "score" ? (r.phishing_score ?? -1) : sort.key === "label" ? (r.class_name ?? "zzz") : sort.key === "status" ? r.status : r.index;
    return data.filter(pass).sort((a, b) => (val(a) > val(b) ? 1 : val(a) < val(b) ? -1 : 0) * sort.dir);
  }, [m.data, filter, sort]);

  const exportCsv = () => {
    const out = [["url", "status", "prediction", "phishing_score", "error"], ...rows.map((r) => [urls[r.index] ?? "", r.status, r.class_name ?? "", r.phishing_score != null ? r.phishing_score.toFixed(4) : "", r.error?.message ?? ""])];
    const blob = new Blob([toCsv(out)], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "phishguard-results.csv";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const th = (key: SortKey, label: string) => (
    <th scope="col" aria-sort={sort.key === key ? (sort.dir === 1 ? "ascending" : "descending") : "none"} className="py-2 pr-4 font-medium">
      <button type="button" className="inline-flex items-center gap-1 hover:text-fog-100" onClick={() => setSort((s) => ({ key, dir: s.key === key ? (s.dir === 1 ? -1 : 1) : 1 }))}>
        {label}{sort.key === key && (sort.dir === 1 ? <ArrowUp className="h-3 w-3" aria-hidden /> : <ArrowDown className="h-3 w-3" aria-hidden />)}
      </button>
    </th>
  );

  return (
    <>
      <PageHeader title="Batch Analysis" subtitle={`Check up to ${MAX_BATCH} URLs at once. Nothing is visited.`} />
      <Card>
        <label htmlFor="batch-input" className="mb-2 block text-sm font-medium">URLs, one per line</label>
        <textarea id="batch-input" value={text} onChange={(e) => { setText(e.target.value); setInputError(null); }} rows={7} spellCheck={false}
          placeholder={"https://example.com/login\nhttp://203.0.113.5/secure/update.php"}
          aria-invalid={!!inputError} aria-describedby="batch-help"
          className="w-full rounded-lg border border-line bg-ink-900 px-4 py-3 font-mono text-sm placeholder:text-fog-600 focus:border-teal-400" />
        <div id="batch-help" className="mt-2 min-h-[1.25rem] text-sm">
          {inputError ? <p role="alert" className="text-risk-300">{inputError}</p> : <p className="text-fog-500">Paste URLs or upload a CSV/TXT file (first column or a column named “url”).</p>}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button type="button" className="btn-primary" onClick={run} disabled={m.isPending}>
            {m.isPending ? <><Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" aria-hidden /> Analyzing…</> : "Analyze URLs"}
          </button>
          <input ref={fileRef} id="batch-file" type="file" accept=".csv,.txt,text/csv,text/plain" className="sr-only" onChange={(e) => onFile(e.target.files?.[0])} />
          <label htmlFor="batch-file" className="btn-secondary cursor-pointer focus-within:outline focus-within:outline-2 focus-within:outline-teal-400"><Upload className="h-4 w-4" aria-hidden /> Upload CSV or TXT</label>
        </div>
      </Card>

      <div className="mt-6">
        {m.isError && <ErrorState error={m.error} />}
        {!m.data && !m.isPending && !m.isError && <EmptyState title="No results yet" body="Results appear here as a table you can sort, filter and export." />}
        {m.data && (
          <Card>
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <Badge tone="teal">{m.data.ok} analyzed</Badge>
                <Badge tone={m.data.invalid ? "amber" : "neutral"}>{m.data.invalid} invalid</Badge>
                <Badge tone="risk">{m.data.results.filter((r) => r.class_name === "phishing").length} flagged as phishing</Badge>
              </div>
              <div className="flex items-center gap-2">
                <label htmlFor="filter" className="text-sm text-fog-500">Show</label>
                <select id="filter" value={filter} onChange={(e) => setFilter(e.target.value as Filter)} className="rounded-lg border border-line bg-ink-900 px-3 py-2 text-sm">
                  <option value="all">All</option><option value="phishing">Potential phishing</option><option value="legitimate">Likely legitimate</option><option value="invalid">Invalid input</option>
                </select>
                <button type="button" className="btn-secondary" onClick={exportCsv} disabled={rows.length === 0}><Download className="h-4 w-4" aria-hidden /> Export CSV</button>
              </div>
            </div>
            {rows.length === 0 ? <EmptyState title="No rows match this filter" body="Change the filter to see the other results." /> : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-sm">
                  <caption className="sr-only">Batch prediction results</caption>
                  <thead><tr className="border-b border-line text-fog-500">{th("index", "#")}<th scope="col" className="py-2 pr-4 font-medium">URL</th>{th("label", "Assessment")}{th("score", "Score")}{th("status", "Status")}</tr></thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={r.index} className="border-b border-line/60 align-top last:border-0">
                        <td className="py-2 pr-4 tabular-nums text-fog-500">{r.index + 1}</td>
                        <td className="max-w-[320px] truncate py-2 pr-4 font-mono text-xs" title={urls[r.index]}>{urls[r.index]}</td>
                        <td className="py-2 pr-4">{r.status === "ok" ? <Badge tone={r.class_name === "phishing" ? "risk" : "teal"}>{r.label}</Badge> : <span className="text-fog-500">Not analyzed</span>}</td>
                        <td className="py-2 pr-4 tabular-nums">{r.phishing_score != null ? pct(r.phishing_score, 1) : "n/a"}</td>
                        <td className="py-2 pr-4">{r.status === "ok" ? <span className="text-fog-300">OK</span> : <span className="text-amber-300">Invalid: {r.error?.message}</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        )}
      </div>
      <div className="mt-6"><Notice tone="teal">Scores are model estimates. Batch mode skips per-URL explanations; open a single URL in the analyzer to see them.</Notice></div>
    </>
  );
}
