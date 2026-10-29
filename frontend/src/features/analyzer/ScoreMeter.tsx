import { pct } from "../../utils/format";

/** Bar from 0-100% with the decision threshold marked. The score is a model estimate, not a calibrated probability. */
export function ScoreMeter({ score, threshold, phishing }: { score: number; threshold: number; phishing: boolean }) {
  const s = Math.min(1, Math.max(0, score)) * 100;
  const t = Math.min(1, Math.max(0, threshold)) * 100;
  return (
    <div>
      <div
        role="meter" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Number(s.toFixed(1))}
        aria-label={`Model-estimated phishing score ${pct(score, 1)}; decision threshold ${pct(threshold, 1)}`}
        className="relative h-3 rounded-full bg-ink-700"
      >
        <div className={`absolute inset-y-0 left-0 rounded-full ${phishing ? "bg-risk-400" : "bg-teal-400"}`} style={{ width: `${s}%` }} />
        <div className="absolute -inset-y-1.5 w-0.5 bg-fog-100" style={{ left: `${t}%` }} aria-hidden />
      </div>
      <div className="relative mt-2 h-5 text-xs text-fog-500">
        <span className="absolute left-0">0%</span>
        <span className="absolute -translate-x-1/2 whitespace-nowrap text-fog-300" style={{ left: `clamp(15%, ${t}%, 85%)` }}>threshold {pct(threshold, 1)}</span>
        <span className="absolute right-0">100%</span>
      </div>
    </div>
  );
}
