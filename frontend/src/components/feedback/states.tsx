import { Loader2, RefreshCw, ServerCrash, FlaskConical } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError } from "../../services/api";

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div role="status" className="flex items-center gap-3 py-10 text-fog-500">
      <Loader2 className="h-5 w-5 animate-spin motion-reduce:animate-none" aria-hidden />
      <span>{label}…</span>
    </div>
  );
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-lg border border-dashed border-line p-6">
      <p className="font-medium">{title}</p>
      <p className="max-w-prose text-sm text-fog-500">{body}</p>
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const e = error instanceof ApiError ? error : null;
  const notReady = e && (e.code === "report_unavailable" || e.code === "model_unavailable");
  return (
    <div role="alert" className="flex flex-col items-start gap-3 rounded-lg border border-line bg-ink-850 p-5">
      <div className="flex items-center gap-2 font-medium">
        {notReady ? <FlaskConical className="h-5 w-5 text-amber-400" aria-hidden /> : <ServerCrash className="h-5 w-5 text-risk-400" aria-hidden />}
        {notReady ? "Not evaluated yet" : "Something went wrong"}
      </div>
      <p className="max-w-prose text-sm text-fog-300">{error instanceof Error ? error.message : "Unexpected error."}</p>
      {notReady && (
        <p className="max-w-prose text-sm text-fog-500">
          Run <code className="rounded bg-ink-700 px-1.5 py-0.5 font-mono text-xs">python -m app.ml.train --csv &lt;path&gt;</code> in the backend folder, then restart the API.
        </p>
      )}
      {onRetry && (
        <button type="button" className="btn-secondary" onClick={onRetry}>
          <RefreshCw className="h-4 w-4" aria-hidden /> Try again
        </button>
      )}
    </div>
  );
}
