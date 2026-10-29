import type { ExplanationItem } from "../../types/api";
import { Card, CardTitle } from "../../components/common/ui";
import { num } from "../../utils/format";

function formatValue(name: string, v: number): string {
  if (name.startsWith("is_") || name.startsWith("has_")) return v ? "yes" : "no";
  return Number.isInteger(v) ? num(v) : v.toFixed(3);
}

export function ExplanationPanel({ items, method, unit }: { items: ExplanationItem[] | null; method: string | null; unit: string | null }) {
  if (!items || items.length === 0) {
    return (
      <Card>
        <CardTitle>Why the model said this</CardTitle>
        <p className="text-sm text-fog-500">No explanation is available for this result.</p>
      </Card>
    );
  }
  const max = Math.max(...items.map((i) => Math.abs(i.contribution)));
  return (
    <Card>
      <CardTitle hint={`Computed from the trained model with ${method ?? "the model's own weights"}. Bars show how far each feature moved the score (${unit}); they describe the model, not proof about the URL.`}>
        Why the model said this
      </CardTitle>
      <ul className="space-y-4">
        {items.map((i) => {
          const toward = i.direction === "toward_phishing";
          const w = Math.max(4, (Math.abs(i.contribution) / max) * 100);
          return (
            <li key={i.feature}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-sm font-medium">{i.label}</span>
                <span className="font-mono text-sm tabular-nums text-fog-300">{formatValue(i.feature, i.value)}</span>
              </div>
              <div className="mt-1.5 h-1.5 rounded-full bg-ink-700" aria-hidden>
                <div className={`h-full rounded-full ${toward ? "bg-risk-400" : "bg-teal-400"}`} style={{ width: `${w}%` }} />
              </div>
              <p className="mt-1 text-xs text-fog-500">
                {toward ? "Pushed the score toward phishing" : "Pushed the score toward legitimate"}
                {i.training_percentile != null && ` · higher than about ${Math.round(i.training_percentile)}% of training URLs`}
              </p>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
