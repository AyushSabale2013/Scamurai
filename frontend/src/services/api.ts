import type {
  AnalyticsSummary, ApiErrorBody, BatchResponse, EvaluationReport, Health, ModelInfo, PredictionResult,
} from "../types/api";

export const API_BASE: string = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") ?? "http://localhost:8000";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { headers: { "Content-Type": "application/json" }, ...init });
  } catch {
    throw new ApiError(0, "network_error", `Cannot reach the PhishGuard API at ${API_BASE}. Check that the backend is running.`);
  }
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    if (res.ok) throw new ApiError(res.status, "invalid_response", "The server returned a response that is not valid JSON.");
  }
  if (!res.ok) {
    const e = (body as ApiErrorBody | null)?.error;
    throw new ApiError(res.status, e?.code ?? "http_error", e?.message ?? `Request failed with status ${res.status}.`);
  }
  return body as T;
}

export const api = {
  health: () => request<Health>("/api/health"),
  modelInfo: () => request<ModelInfo>("/api/model-info"),
  summary: () => request<AnalyticsSummary>("/api/analytics/summary"),
  metrics: () => request<EvaluationReport>("/api/model-metrics"),
  predict: (url: string, explain = true) =>
    request<PredictionResult>("/api/predict", { method: "POST", body: JSON.stringify({ url, explain }) }),
  predictBatch: (urls: string[]) =>
    request<BatchResponse>("/api/predict/batch", { method: "POST", body: JSON.stringify({ urls, explain: false }) }),
};
