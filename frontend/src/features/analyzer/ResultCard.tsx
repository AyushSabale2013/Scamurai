import { ShieldAlert, ShieldCheck } from "lucide-react";
import type { PredictionResult } from "../../types/api";
import { pct } from "../../utils/format";
import { Card, Notice } from "../../components/common/ui";
import { ScoreMeter } from "./ScoreMeter";
import { UrlAnatomy } from "./UrlAnatomy";

export function ResultCard({ result, pathWarning }: { result: PredictionResult; pathWarning: boolean }) {
  const phishing = result.class_name === "phishing";
  const parts = result.url_parts;
  const hasPath = !!parts && ((parts.path && parts.path !== "/") || !!parts.query || !!parts.fragment);
  return (
    <Card aria-live="polite" aria-label="Prediction result" className={phishing ? "border-risk-500/60" : undefined}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          {phishing ? <ShieldAlert className="mt-0.5 h-8 w-8 text-risk-400" aria-hidden /> : <ShieldCheck className="mt-0.5 h-8 w-8 text-teal-400" aria-hidden />}
          <div>
            <p className="text-xs text-fog-500">Model assessment</p>
            <h2 className={`text-2xl font-semibold ${phishing ? "text-risk-300" : "text-fog-100"}`}>{result.label}</h2>
          </div>
        </div>
        <div className="text-right">
          <p className="text-xs text-fog-500">Model-estimated phishing score</p>
          <p className="text-2xl font-semibold tabular-nums">{pct(result.phishing_score, 1)}</p>
        </div>
      </div>

      <div className="mt-5"><ScoreMeter score={result.phishing_score} threshold={result.threshold} phishing={phishing} /></div>
      <p className="mt-1 text-xs text-fog-500">
        The score is the model’s output, not a calibrated real-world probability. The URL is flagged when the score reaches the decision threshold ({pct(result.threshold, 1)}).
      </p>

      {parts && <div className="mt-6"><UrlAnatomy parts={parts} /></div>}

      <div className="mt-5 space-y-3">
        {phishing ? (
          <Notice tone="risk" title="Be careful with this link">
            Do not enter passwords or payment details until you have confirmed the sender and the destination through another channel.
          </Notice>
        ) : (
          <Notice tone="teal" title="This is not a guarantee of safety">
            A low score only means the URL’s text resembles legitimate examples the model was trained on.
          </Notice>
        )}
        {pathWarning && hasPath && (
          <Notice tone="amber" title="This URL has a path or query">
            In the training data, no legitimate URL had a path or query, so the model tends to score such URLs as phishing. Treat this result as weak evidence in either direction.
          </Notice>
        )}
        {result.notes.map((n) => <Notice key={n} tone="teal">{n} HTTPS is a model input, so a URL without a scheme may score higher.</Notice>)}
      </div>
    </Card>
  );
}
