import { useMemo, useState } from "react";
import { ClassDistributionChart } from "../components/charts/ClassDistributionChart";
import { Card, CardTitle, DataTable, Notice, PageHeader, Stat } from "../components/common/ui";
import { ErrorState, LoadingState } from "../components/feedback/states";
import { useModelInfo, useSummary } from "../hooks/useApi";
import { experimentLabel, num, pct } from "../utils/format";

export function DatasetPage() {
  const s = useSummary();
  const info = useModelInfo();
  const [q, setQ] = useState("");
  const defs = info.data?.feature_definitions;
  const filtered = useMemo(() => Object.entries(defs ?? {}).filter(([k, v]) => (k + v.label + v.description).toLowerCase().includes(q.toLowerCase())), [defs, q]);

  if (s.isLoading) return <><PageHeader title="Dataset Explorer" /><LoadingState label="Loading dataset audit" /></>;
  if (s.isError || !s.data) return <><PageHeader title="Dataset Explorer" /><ErrorState error={s.error} onRetry={() => s.refetch()} /></>;
  const d = s.data.dataset, c = s.data.cleaning, sh = d.shortcut_analysis;

  return (
    <>
      <PageHeader title="Dataset Explorer" subtitle="How the PhiUSIIL dataset was inspected and prepared. Statistics are recomputed from the file at training time." />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Original rows" value={num(d.raw_rows)} note={`${d.columns} columns`} />
        <Stat label="Cleaned rows" value={num(d.clean_rows)} note={`${num(d.raw_rows - d.clean_rows)} removed`} />
        <Stat label="Duplicate URL rows" value={num(d.duplicate_url_rows)} note={`${d.conflicting_duplicate_groups} with conflicting labels`} />
        <Stat label="Missing values" value={num(d.missing_values)} note="across all original columns" />
        <Stat label="Model features" value={num(d.model_features)} note="derived from the URL text only" />
        <Stat label="Registrable domains" value={num(d.unique_registrable_domains)} note={`${c.domains_with_mixed_labels} contain both labels`} />
        <Stat label="Phishing / legitimate" value={`${num(d.label_counts_clean["0"])} / ${num(d.label_counts_clean["1"])}`} note="after cleaning" />
        <Stat label="Label mapping" value="0 = phishing · 1 = legitimate" note="matches the dataset documentation" />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card><CardTitle>Class distribution (cleaned)</CardTitle><ClassDistributionChart counts={d.label_counts_clean} /></Card>
        <Card>
          <CardTitle>Data-cleaning summary</CardTitle>
          <DataTable caption="Records removed by step" head={["Step", "Rows"]} rows={[
            ["Rows in", num(c.rows_in)],
            ["Exact duplicate URLs removed", num(c.exact_duplicate_rows_removed)],
            ["Near-duplicates removed (same label)", num(c.near_duplicate_rows_removed_same_label)],
            ["Rejected by the feature extractor", num(c.dropped_by_extractor_total)],
            ["Rows out", num(c.rows_out)],
          ]} />
          <p className="mt-3 text-xs text-fog-500">Near-duplicates differ only by letter case or a trailing slash. Conflicting-label duplicates would be dropped entirely; none were found among exact duplicates.</p>
        </Card>
      </div>

      <Card className="mt-6">
        <CardTitle>Data-quality warnings</CardTitle>
        <div className="space-y-3">
          <Notice tone="amber" title="Collection pattern in the legitimate class">
            {sh.finding}
            <DataTable className="mt-3" caption="Share of URLs by pattern" head={["Pattern", "Phishing", "Legitimate"]} rows={[
              ["Uses https", pct(sh.share_https_scheme.phishing, 1), pct(sh.share_https_scheme.legitimate, 1)],
              ["Starts with www.", pct(sh.share_www_prefix.phishing, 1), pct(sh.share_www_prefix.legitimate, 1)],
              ["Has a path, query or fragment", pct(sh.share_with_path_query_or_fragment.phishing, 1), pct(sh.share_with_path_query_or_fragment.legitimate, 1)],
              ["https://www.host with no path", pct(sh.share_matching_template_https_www_no_path.phishing, 1), pct(sh.share_matching_template_https_www_no_path.legitimate, 1)],
            ]} />
          </Notice>
          <Notice tone="amber" title="Shared hosting and repeated domains">
            {num(Number(c.domains_with_multiple_urls ?? 0))} domains appear more than once, and a few hosting domains contribute thousands of URLs. A stratified split lets a domain land in train and test, so the domain-grouped experiment is the more conservative one.
          </Notice>
        </div>
      </Card>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        {Object.entries(s.data.splits).map(([k, v]) => (
          <Card key={k}>
            <CardTitle hint={v.description}>{experimentLabel(k)} split</CardTitle>
            <DataTable caption={`${k} partition counts`} head={["Partition", "Rows", "Phishing", "Legitimate", "Domains"]}
              rows={(["train", "val", "test"] as const).map((p) => [p === "val" ? "validation" : p, num(v.split[p].rows), num(v.split[p].labels.phishing), num(v.split[p].labels.legitimate), num(v.split[p].domains)])} />
            <p className="mt-3 text-xs text-fog-500">Domains shared between partitions: train/test {num(v.verification.domain_overlap["train-test"])}, train/validation {num(v.verification.domain_overlap["train-val"])}, validation/test {num(v.verification.domain_overlap["val-test"])}. URL overlap is 0 in both experiments.</p>
          </Card>
        ))}
      </div>

      <Card className="mt-6">
        <CardTitle hint="The model uses only values that can be computed from the URL string, so it does not use all 54 original dataset features.">Why webpage columns were excluded</CardTitle>
        <DataTable caption="Excluded columns" head={["Column(s)", "Reason"]} rows={Object.entries(d.excluded_columns).map(([k, v]) => [<span key={k} className="text-left">{k}</span>, <span key={v} className="block max-w-md text-left text-fog-300">{v}</span>])} />
      </Card>

      <Card className="mt-6">
        <CardTitle hint="Definitions are stored in the model metadata and shared by training and prediction.">Feature dictionary ({defs ? Object.keys(defs).length : 0} features)</CardTitle>
        <label htmlFor="fq" className="sr-only">Filter features</label>
        <input id="fq" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter features" className="mb-3 w-full max-w-xs rounded-lg border border-line bg-ink-900 px-3 py-2 text-sm focus:border-teal-400" />
        {info.isError ? <ErrorState error={info.error} /> : (
          <div className="overflow-x-auto"><table className="w-full min-w-[560px] text-left text-sm"><caption className="sr-only">Feature dictionary</caption>
            <thead><tr className="border-b border-line text-fog-500"><th scope="col" className="py-2 pr-4 font-medium">Feature</th><th scope="col" className="py-2 pr-4 font-medium">Name in code</th><th scope="col" className="py-2 font-medium">Definition</th></tr></thead>
            <tbody>{filtered.map(([k, v]) => <tr key={k} className="border-b border-line/60 last:border-0"><td className="py-2 pr-4">{v.label}</td><td className="py-2 pr-4 font-mono text-xs text-fog-300">{k}</td><td className="py-2 text-fog-300">{v.description}</td></tr>)}</tbody></table></div>
        )}
      </Card>

      <Card className="mt-6">
        <CardTitle>Citation and license</CardTitle>
        <p className="max-w-prose text-sm text-fog-300">{info.data?.dataset.citation ?? "Prasad, A. & Chandra, S. PhiUSIIL Phishing URL (Website). UCI Machine Learning Repository."}</p>
        <p className="mt-2 text-sm text-fog-300">License: {info.data?.dataset.license ?? "CC BY 4.0"} · Source: {info.data?.dataset.source ?? "UCI ML Repository #967"}</p>
        <p className="mt-2 break-all font-mono text-xs text-fog-500">File SHA-256: {d.file_sha256}</p>
      </Card>
    </>
  );
}
