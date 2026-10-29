import { Link } from "react-router-dom";
import { ClassDistributionChart } from "../components/charts/ClassDistributionChart";
import { ConfusionMatrix } from "../components/charts/ConfusionMatrix";
import { FeatureImportanceChart } from "../components/charts/FeatureImportanceChart";
import { ModelComparisonChart } from "../components/charts/ModelComparisonChart";
import { CurveChart } from "../components/charts/PRCurveChart";
import { Card, CardTitle, Notice, PageHeader, Stat } from "../components/common/ui";
import { EmptyState, ErrorState, LoadingState } from "../components/feedback/states";
import { useMetrics, useSummary } from "../hooks/useApi";
import { useRecent } from "../hooks/recent";
import { experimentLabel, ms, num, pct } from "../utils/format";

export function OverviewPage() {
  const s = useSummary();
  const r = useMetrics();
  const recent = useRecent();
  const na = "Not evaluated yet";
  const h = s.data?.headline;
  const exp = r.data?.headline_experiment ?? "domain_grouped";
  const chosen = r.data?.selected.chosen;
  const chosenReport = chosen ? r.data?.experiments[exp]?.models[chosen] : undefined;

  return (
    <>
      <PageHeader title="Security Overview" subtitle="URL risk analysis powered by machine learning."
        actions={<><Link to="/analyzer" className="btn-primary">Analyze a URL</Link><Link to="/model-lab" className="btn-secondary">View Model Performance</Link></>} />

      {s.data && (
        <div className="mb-6">
          <Notice tone="amber" title="Read the scores with the dataset in mind">
            In the training data, {pct(s.data.dataset.shortcut_analysis.share_matching_template_https_www_no_path.legitimate, 1)} of legitimate URLs are plain
            https://www.<i>host</i> homepages. Strong scores here partly reflect that pattern, so real legitimate URLs with paths may be flagged.{" "}
            <Link to="/model-lab" className="text-teal-300 underline">See the diagnostics</Link>.
          </Notice>
        </div>
      )}

      {s.isLoading && <LoadingState label="Loading evaluation results" />}
      {s.isError && <ErrorState error={s.error} onRetry={() => s.refetch()} />}

      <div className="mt-2 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Dataset records" value={s.data ? num(s.data.dataset.raw_rows) : na} note={s.data && `${num(s.data.dataset.clean_rows)} after cleaning`} />
        <Stat label="Phishing recall" value={h ? pct(h.phishing_recall, 2) : na} note={h && `${experimentLabel(h.experiment)} test set`} />
        <Stat label="Selected model" value={h?.display_name ?? na} note={h && `F1 ${pct(h.phishing_f1, 2)} · PR-AUC ${h.pr_auc.toFixed(4)}`} />
        <Stat label="Inference latency" value={h ? ms(h.latency_p50_ms) : na} note="Model only, single URL, median" />
      </div>

      {r.isError && <div className="mt-6"><ErrorState error={r.error} onRetry={() => r.refetch()} /></div>}
      {r.data && s.data && (
        <div className="mt-6 grid gap-6 lg:grid-cols-2">
          <Card><CardTitle hint={`Phishing-class scores on the ${experimentLabel(exp).toLowerCase()} test set.`}>Model comparison</CardTitle><ModelComparisonChart rows={s.data.models} experiment={exp} /></Card>
          <Card><CardTitle hint="Counts on the test set at the validation-tuned threshold.">Confusion matrix · {chosenReport?.display_name}</CardTitle>{chosenReport && <ConfusionMatrix metrics={chosenReport.test} title={experimentLabel(exp) + " test set"} />}</Card>
          <Card><CardTitle>Precision-recall curve</CardTitle><CurveChart models={r.data.experiments[exp].models} kind="pr" /></Card>
          <Card><CardTitle hint="Cleaned dataset, after removing duplicates.">Class distribution</CardTitle><ClassDistributionChart counts={s.data.dataset.label_counts_clean} /></Card>
          <Card className="lg:col-span-2"><CardTitle hint={`${r.data.feature_importance.method}, averaged over ${num(r.data.feature_importance.sample_rows)} test URLs. These show what the model relies on, not what makes a URL malicious.`}>Feature importance</CardTitle>
            <FeatureImportanceChart rows={r.data.feature_importance.selected_model_shap} unit={r.data.feature_importance.unit} /></Card>
        </div>
      )}

      <Card className="mt-6">
        <CardTitle hint="Kept in this browser tab only. Only the domain and result are stored, never the full URL.">Recent analyses</CardTitle>
        {recent.items.length === 0 ? (
          <EmptyState title="Nothing analyzed in this session" body="Results from the URL Analyzer will be listed here until you close the tab." action={<Link to="/analyzer" className="btn-secondary">Start an analysis</Link>} />
        ) : (
          <>
            <ul className="divide-y divide-line/60 text-sm">
              {recent.items.map((i) => (
                <li key={i.at} className="flex items-center justify-between gap-3 py-2">
                  <span className="truncate font-mono">{i.domain}</span>
                  <span className="shrink-0 text-fog-300">{i.className === "phishing" ? "Potential phishing" : "Likely legitimate"} · {pct(i.score, 1)}</span>
                </li>
              ))}
            </ul>
            <button type="button" className="btn-ghost mt-2 -ml-2 px-2 py-1.5" onClick={recent.clear}>Clear history</button>
          </>
        )}
      </Card>
    </>
  );
}
