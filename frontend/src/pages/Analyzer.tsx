import { useMutation } from "@tanstack/react-query";
import { ExplanationPanel } from "../features/analyzer/ExplanationPanel";
import { FeatureTable } from "../features/analyzer/FeatureTable";
import { ResultCard } from "../features/analyzer/ResultCard";
import { UrlForm } from "../features/analyzer/UrlForm";
import { Card, Notice, PageHeader } from "../components/common/ui";
import { EmptyState, ErrorState } from "../components/feedback/states";
import { useSummary } from "../hooks/useApi";
import { useRecent } from "../hooks/recent";
import { api } from "../services/api";

export function AnalyzerPage() {
  const recent = useRecent();
  const { data: summary } = useSummary();
  const m = useMutation({
    mutationFn: (url: string) => api.predict(url, true),
    onSuccess: (r) => {
      // Session memory only; store the registered domain, never the full URL or query string.
      recent.add({ at: Date.now(), domain: r.url_parts?.registered_domain ?? "unknown", className: r.class_name, score: r.phishing_score });
    },
  });
  const legitWithPath = summary?.dataset.shortcut_analysis.share_with_path_query_or_fragment.legitimate;
  const pathWarning = legitWithPath !== undefined && legitWithPath < 0.01;

  return (
    <>
      <PageHeader title="URL Analyzer" subtitle="Paste a link to get a machine learning risk assessment before you click it." />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="space-y-6">
          <UrlForm busy={m.isPending} onSubmit={(u) => m.mutate(u)} />
          {m.isPending && <div role="status" className="card card-pad text-fog-300">Running the model…</div>}
          {m.isError && <ErrorState error={m.error} />}
          {m.data && !m.isPending && <ResultCard result={m.data} pathWarning={pathWarning} />}
          {!m.data && !m.isPending && !m.isError && (
            <EmptyState title="No URL analyzed yet" body="Enter a URL above. The result shows the model’s verdict, its score, and the features that moved it." />
          )}
          <Notice tone="teal" title="Safety notice">
            Machine learning predictions are estimates, not guarantees. A legitimate-looking URL may still be malicious. Verify the sender and destination before sharing credentials or sensitive information.
          </Notice>
        </div>
        <div className="space-y-6">
          {m.data && !m.isPending ? (
            <>
              <ExplanationPanel items={m.data.explanation} method={m.data.explanation_method} unit={m.data.explanation_unit} />
              <FeatureTable features={m.data.features} />
            </>
          ) : (
            <Card>
              <p className="text-sm text-fog-500">Feature values and the model’s explanation appear here after you analyze a URL.</p>
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
