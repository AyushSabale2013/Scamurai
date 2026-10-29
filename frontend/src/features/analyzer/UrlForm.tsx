import { ClipboardPaste, Eraser, Loader2, ScanSearch } from "lucide-react";
import { useId, useRef, useState } from "react";
import { validateUrlInput } from "../../utils/validateUrl";

export function UrlForm({ onSubmit, busy }: { onSubmit: (url: string) => void; busy: boolean }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);
  const ref = useRef<HTMLInputElement>(null);
  const id = useId();
  const canPaste = typeof navigator !== "undefined" && !!navigator.clipboard?.readText;

  const submit = () => {
    if (busy) return;
    const err = validateUrlInput(value);
    setError(err);
    if (err) { ref.current?.focus(); return; }
    onSubmit(value.trim());
  };

  return (
    <div className="card card-pad">
      <label htmlFor={id} className="mb-2 block text-sm font-medium">URL to analyze</label>
      <div className="flex flex-col gap-3 sm:flex-row">
        <input
          id={id} ref={ref} type="text" inputMode="url" autoComplete="off" autoCapitalize="off" spellCheck={false}
          value={value} placeholder="https://example.com/account/verify"
          aria-invalid={!!error} aria-describedby={`${id}-help`}
          onChange={(e) => { setValue(e.target.value); if (error) setError(null); }}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } }}
          className="min-w-0 flex-1 rounded-lg border border-line bg-ink-900 px-4 py-3 font-mono text-sm placeholder:text-fog-600 focus:border-teal-400"
        />
        <button type="button" className="btn-primary sm:w-40" onClick={submit} disabled={busy}>
          {busy ? <><Loader2 className="h-4 w-4 animate-spin motion-reduce:animate-none" aria-hidden /> Analyzing…</> : <><ScanSearch className="h-4 w-4" aria-hidden /> Analyze</>}
        </button>
      </div>
      <div id={`${id}-help`} className="mt-3 min-h-[1.25rem] text-sm">
        {error ? <p role="alert" className="text-risk-300">{error}</p> : <p className="text-fog-500">PhishGuard reads the URL as text only. It never opens or downloads the site.</p>}
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {canPaste && (
          <button type="button" className="btn-secondary py-1.5" onClick={async () => { try { setValue(await navigator.clipboard.readText()); setError(null); ref.current?.focus(); } catch { setError("Clipboard access was blocked. Paste with Ctrl+V instead."); } }}>
            <ClipboardPaste className="h-4 w-4" aria-hidden /> Paste from clipboard
          </button>
        )}
        <button type="button" className="btn-secondary py-1.5" onClick={() => { setValue(""); setError(null); ref.current?.focus(); }} disabled={!value}>
          <Eraser className="h-4 w-4" aria-hidden /> Clear
        </button>
      </div>
    </div>
  );
}
