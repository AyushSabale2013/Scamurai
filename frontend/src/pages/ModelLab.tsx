import { useState } from "react";
import { ConfusionMatrix } from "../components/charts/ConfusionMatrix";
import { FeatureImportanceChart } from "../components/charts/FeatureImportanceChart";
import { ModelComparisonChart } from "../components/charts/ModelComparisonChart";
import { CurveChart } from "../components/charts/PRCurveChart";
import { Badge, Card, CardTitle, DataTable, Notice, PageHeader, Stat } from "../components/common/ui";
import { ErrorState, LoadingState } from "../components/feedback/states";
import { useMetrics, useSummary } from "../hooks/useApi";
import { bytes, experimentLabel, ms, num, pct, secs } from "../utils/format";

const ORDER = ["logistic_regression", "random_forest", "xgboost"];

export function ModelLabPage() {
  const r = useMetrics();
  const s = useSummary();
  const [exp, setExp] = useState("domain_grouped");

  if (r.isLoading || s.isLoading) return <><PageHeader title="Model Lab" /><LoadingState label="Loading evaluation report" /></>;
  if (r.isError || s.isError || !r.data || !s.data) return <><PageHeader title="Model Lab" /><ErrorState error={r.error ?? s.error} onRetry={() => { r.refetch(); s.refetch(); }} /></>;

  const rep = r.data, sum = s.data;
  const chosen = rep.selected.chosen;
  const models = rep.experiments[exp].models;
  const sel = models[chosen];
  const sd = rep.shortcut_diagnostics;
  const rule = sd.rule_baseline_domain_grouped_test;
  const slice = sd.selected_model_on_template_slice_domain_grouped_test;

  return (
    <>
      <PageHeader title="Model Lab" subtitle="Every number on this page comes from the saved evaluation report."
        actions={
          <div role="group" aria-label="Evaluation experiment" className="inline-flex rounded-lg border border-line p-0.5">
            {Object.keys(rep.experiments).map((k) => (
              <button key={k} type="button" aria-pressed={exp === k} onClick={() => setExp(k)}
                className={`rounded-md px-3 py-1.5 text-sm ${exp === k ? "bg-teal-600/25 text-teal-300" : "text-fog-300 hover:text-fog-100"}`}>{experimentLabel(k)}</button>
            ))}
          </div>} />

      <Notice tone="amber" title="Why these scores are probably optimistic">
        {sd.summary}
      </Notice>

      <p className="mt-6 max-w-prose text-sm text-fog-300">{rep.experiments[exp].description} The two experiments are never averaged together.</p>

      <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Phishing recall" value={pct(sel.test.per_class.phishing.recall, 2)} note={`${num(sel.test.confusion_matrix.matrix[0][1])} phishing URLs missed`} />
        <Stat label="Phishing precision" value={pct(sel.test.per_class.phishing.precision, 2)} note={`${num(sel.test.confusion_matrix.matrix[1][0])} legitimate URLs flagged`} />
        <Stat label="PR-AUC / ROC-AUC" value={`${sel.test.pr_auc_phishing?.toFixed(4)} / ${sel.test.roc_auc?.toFixed(4)}`} note={`${sel.display_name}, ${experimentLabel(exp)} test`} />
        <Stat label="Latency · size" value={`${ms(sel.latency.p50_ms)} · ${bytes(sel.model_size_bytes)}`} note={`Training ${secs(sel.fit_seconds)}`} />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardTitle hint={rep.selected.rule}>Selected model: {models[chosen].display_name}</CardTitle>
          <p className="mb-3 text-sm text-fog-300">{rep.selected.reason}</p>
          <DataTable caption="Selection candidates (domain-grouped validation)" head={["Model", "Val F1", "Val recall", "Val precision", "Latency", "Tied for best"]}
            rows={rep.selected.candidates.map((c) => [models[c.model]?.display_name ?? c.model, c.val_phishing_f1.toFixed(4), pct(c.val_phishing_recall, 2), pct(c.val_phishing_precision, 2), ms(c.p50_latency_ms), c.eligible ? <Badge tone="teal">yes</Badge> : "no"])} />
          {rep.selected.rule_revision_note && <p className="mt-3 text-xs text-fog-500">{rep.selected.rule_revision_note}</p>}
        </Card>
        <Card>
          <CardTitle hint="Model comparison on the selected experiment's test set.">Precision, recall and F1</CardTitle>
          <ModelComparisonChart rows={sum.models} experiment={exp} />
        </Card>
      </div>

      <Card className="mt-6">
        <CardTitle>Model comparison table ({experimentLabel(exp)} test set)</CardTitle>
        <DataTable caption="Test metrics for each model" head={["Model", "Accuracy", "Phish P", "Phish R", "Phish F1", "Macro F1", "ROC-AUC", "PR-AUC", "FNR", "FPR", "Threshold"]}
          rows={ORDER.map((n) => { const t = models[n].test; const p = t.per_class.phishing; return [models[n].display_name + (n === chosen ? " ★" : ""), pct(t.accuracy, 3), pct(p.precision, 3), pct(p.recall, 3), pct(p.f1, 3), t.macro_f1.toFixed(4), t.roc_auc?.toFixed(5), t.pr_auc_phishing?.toFixed(5), pct(t.confusion_matrix.phishing_false_negative_rate, 3), pct(t.confusion_matrix.legitimate_false_positive_rate, 3), t.threshold.toFixed(3)]; })} />
        <p className="mt-2 text-xs text-fog-500">★ selected model. FNR: phishing URLs missed. FPR: legitimate URLs flagged. Phishing is the positive class.</p>
      </Card>

      <div className="mt-6 grid gap-6 lg:grid-cols-3">
        {ORDER.map((n) => <Card key={n}><ConfusionMatrix metrics={models[n].test} title={models[n].display_name} /></Card>)}
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card><CardTitle>Precision-recall curves</CardTitle><CurveChart models={models} kind="pr" /></Card>
        <Card><CardTitle>ROC curves</CardTitle><CurveChart models={models} kind="roc" /></Card>
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardTitle hint={`${rep.feature_importance.method} on ${num(rep.feature_importance.sample_rows)} test URLs. Importance is not causation and does not prove a URL is malicious.`}>Feature importance</CardTitle>
          <FeatureImportanceChart rows={rep.feature_importance.selected_model_shap} unit={rep.feature_importance.unit} />
        </Card>
        <Card>
          <CardTitle hint="Tuned on validation data only to maximise F2 (recall counts four times as much as precision). The test set was never used.">Threshold selection</CardTitle>
          <DataTable caption="Validation-tuned thresholds" head={["Model", "Threshold", "Val recall", "Val precision", "Val F2"]}
            rows={ORDER.map((n) => { const t = models[n].threshold; return [models[n].display_name, t.threshold.toFixed(3), pct(t.val_recall, 2), pct(t.val_precision, 2), t.val_fbeta.toFixed(4)]; })} />
          <h3 className="mb-2 mt-6 text-sm font-semibold">Training time and inference</h3>
          <DataTable caption="Cost per model" head={["Model", "Fit", "Tuning (all)", "Latency p50", "p95", "Size"]}
            rows={ORDER.map((n) => [models[n].display_name, secs(models[n].fit_seconds), secs(models[n].tuning.tuning_seconds), ms(models[n].latency.p50_ms), ms(models[n].latency.p95_ms), bytes(models[n].model_size_bytes)])} />
        </Card>
      </div>

      <Card className="mt-6">
        <CardTitle hint={`Selected model (${sel.display_name}), ${experimentLabel(exp)} test set. Aggregated counts only, no URLs.`}>Error analysis</CardTitle>
        <DataTable caption="Errors by slice" head={["Slice", "URLs", "Phishing", "Missed phishing", "False alarms", "Error rate"]}
          rows={rep.error_analysis[exp].slices.map((x) => [x.slice, num(x.n), num(x.phishing), num(x.missed_phishing), num(x.false_alarms), pct(x.error_rate, 2)])} />
      </Card>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card>
          <CardTitle hint={sd.template_definition}>Shortcut diagnostics</CardTitle>
          <DataTable caption="Rule baseline versus model" head={["", "Accuracy", "Phish recall", "Phish precision"]}
            rows={[
              ["One-line rule: legitimate only if template", pct(rule.accuracy, 2), pct(rule.per_class.phishing.recall, 2), pct(rule.per_class.phishing.precision, 2)],
              [`${sel.display_name} (all test URLs)`, pct(models[chosen].test.accuracy, 2), pct(models[chosen].test.per_class.phishing.recall, 2), pct(models[chosen].test.per_class.phishing.precision, 2)],
              ...(slice ? [[`${sel.display_name}, template-shaped URLs only`, pct(slice.accuracy, 2), pct(slice.per_class.phishing.recall, 2), pct(slice.per_class.phishing.precision, 2)]] : []),
            ]} />
          <p className="mt-3 text-sm text-fog-300">The last row is the fairest read of what the model learned beyond the pattern: it only counts URLs that look like the legitimate examples. Domain-grouped test set.</p>
        </Card>
        <Card>
          <CardTitle hint={rep.manual_probe.note}>Sanity probe: well-known legitimate URLs</CardTitle>
          <DataTable caption="Manual probe" head={["URL", "Score", "Model says"]}
            rows={rep.manual_probe.results.map((p) => [<span key={p.url} className="font-mono text-xs">{p.url}</span>, pct(p.phishing_score, 1), p.predicted === "phishing" ? <Badge tone="risk">phishing</Badge> : <Badge tone="teal">legitimate</Badge>])} />
        </Card>
      </div>

      <Card className="mt-6">
        <CardTitle>Why recall matters, and why precision does too</CardTitle>
        <div className="grid gap-4 text-sm text-fog-300 md:grid-cols-2">
          <p><strong className="text-fog-100">Recall</strong> is the share of real phishing URLs the model catches. A miss means someone may trust a dangerous link, so the threshold is tuned to favour recall.</p>
          <p><strong className="text-fog-100">Precision</strong> is the share of flagged URLs that really are phishing. Too many false alarms teach people to ignore warnings, so both are reported, together with the false-alarm rate on legitimate URLs.</p>
        </div>
      </Card>
    </>
  );
}
