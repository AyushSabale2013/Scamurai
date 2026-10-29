import { useState } from "react";
import { Card, CardTitle } from "../../components/common/ui";
import { useModelInfo } from "../../hooks/useApi";
import { num } from "../../utils/format";

const KEY = ["url_length", "hostname_length", "subdomain_count", "path_length", "is_https", "is_ip_host", "digit_count", "hyphen_count", "url_entropy", "suspicious_token_count"];

export function FeatureTable({ features }: { features: Record<string, number> }) {
  const [all, setAll] = useState(false);
  const { data } = useModelInfo();
  const defs = data?.feature_definitions ?? {};
  const names = all ? Object.keys(features) : KEY.filter((k) => k in features);
  return (
    <Card>
      <CardTitle hint="Values extracted from the URL text. The same extractor is used for training and for this page.">Extracted features</CardTitle>
      <dl className="divide-y divide-line/60 text-sm">
        {names.map((n) => (
          <div key={n} className="flex items-baseline justify-between gap-4 py-1.5" title={defs[n]?.description}>
            <dt className="text-fog-300">{defs[n]?.label ?? n}</dt>
            <dd className="font-mono tabular-nums">{Number.isInteger(features[n]) ? num(features[n]) : features[n].toFixed(3)}</dd>
          </div>
        ))}
      </dl>
      <button type="button" className="btn-ghost mt-3 -ml-2 px-2 py-1.5 text-teal-300" aria-expanded={all} onClick={() => setAll((v) => !v)}>
        {all ? "Show key features only" : `Show all ${Object.keys(features).length} features`}
      </button>
    </Card>
  );
}
