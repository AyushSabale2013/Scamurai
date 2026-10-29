import type { URLParts } from "../../types/api";

interface Seg { text: string; caption: string; tone: string }

/** Splits the submitted URL (as parsed by the backend) into labelled parts. Pure display of real parse output. */
export function UrlAnatomy({ parts }: { parts: URLParts }) {
  const segs: Seg[] = [];
  segs.push({ text: parts.scheme + "://", caption: parts.scheme_assumed ? "scheme (assumed)" : "scheme", tone: "border-fog-600 text-fog-500" });
  if (parts.subdomain) segs.push({ text: parts.subdomain + ".", caption: "subdomain", tone: "border-amber-400 text-amber-300" });
  segs.push({ text: parts.registered_domain, caption: "registered domain", tone: "border-teal-400 text-teal-300" });
  if (parts.port != null) segs.push({ text: ":" + parts.port, caption: "port", tone: "border-fog-600 text-fog-300" });
  if (parts.path) segs.push({ text: parts.path, caption: "path", tone: "border-periwinkle text-fog-100" });
  if (parts.query) segs.push({ text: "?" + parts.query, caption: "query", tone: "border-periwinkle text-fog-100" });
  if (parts.fragment) segs.push({ text: "#" + parts.fragment, caption: "fragment", tone: "border-fog-600 text-fog-300" });
  return (
    <div className="overflow-x-auto pb-1" aria-label="URL broken into parts">
      <div className="flex w-max min-w-full items-start font-mono text-[15px] leading-tight">
        {segs.map((s, i) => (
          <div key={i} className="flex flex-col pr-0.5">
            <span className={`whitespace-pre border-b-2 pb-1 ${s.tone}`}>{s.text.length > 90 ? s.text.slice(0, 87) + "…" : s.text}</span>
            <span className="mt-1.5 font-sans text-[11px] text-fog-500">{s.caption}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
