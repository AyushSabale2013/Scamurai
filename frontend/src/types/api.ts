export type ClassName = "phishing" | "legitimate";

export interface ExplanationItem {
  feature: string;
  label: string;
  description: string;
  value: number;
  contribution: number;
  direction: "toward_phishing" | "toward_legitimate";
  training_percentile?: number | null;
}

export interface URLParts {
  scheme: string;
  subdomain: string;
  registered_domain: string;
  port: number | null;
  path: string;
  query: string;
  fragment: string;
  scheme_assumed: boolean;
}

export interface PredictionResult {
  predicted_class: 0 | 1;
  class_name: ClassName;
  label: string;
  phishing_score: number;
  threshold: number;
  model_version: string;
  features: Record<string, number>;
  url_parts: URLParts | null;
  explanation: ExplanationItem[] | null;
  explanation_method: string | null;
  explanation_unit: string | null;
  notes: string[];
  disclaimer: string;
}

export interface BatchItem {
  index: number;
  status: "ok" | "invalid";
  predicted_class: 0 | 1 | null;
  class_name: ClassName | null;
  label: string | null;
  phishing_score: number | null;
  notes: string[];
  error: { code: string; message: string } | null;
}

export interface BatchResponse {
  model_version: string;
  threshold: number;
  total: number;
  ok: number;
  invalid: number;
  results: BatchItem[];
  disclaimer: string;
}

export interface Health {
  status: string;
  model_loaded: boolean;
  model_version: string | null;
  detail: string | null;
}

export interface HeadlineMetrics {
  experiment: string;
  model: string;
  display_name: string;
  phishing_recall: number;
  phishing_precision: number;
  phishing_f1: number;
  pr_auc: number;
  accuracy: number;
  latency_p50_ms: number;
  threshold: number;
}

export interface ModelInfo {
  model_name: string;
  model_display_name: string;
  model_version: string;
  trained_at: string;
  feature_count: number;
  feature_names: string[];
  feature_definitions: Record<string, { label: string; description: string }>;
  decision_threshold: number;
  threshold_selection: Record<string, number>;
  class_mapping: Record<string, string>;
  score_definition: string;
  explanation_method: string;
  hyperparameters: Record<string, unknown>;
  preprocessing: Record<string, unknown>;
  dataset: { name: string; source: string; license: string; citation: string; rows_raw: number; rows_clean: number };
  dependencies: Record<string, string>;
  headline_metrics: HeadlineMetrics | null;
}

export interface ModelRow {
  experiment: "stratified" | "domain_grouped";
  model: string;
  display_name: string;
  accuracy: number;
  phishing_precision: number;
  phishing_recall: number;
  phishing_f1: number;
  legitimate_recall: number;
  macro_f1: number;
  weighted_f1: number;
  roc_auc: number;
  pr_auc: number;
  threshold: number;
  fit_seconds: number;
  tuning_seconds: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  model_size_bytes: number;
  false_negative_rate: number;
  false_positive_rate: number;
}

export interface SplitPart {
  rows: number;
  share: number;
  labels: { phishing: number; legitimate: number };
  phishing_share: number;
  domains: number;
}

export interface AnalyticsSummary {
  generated_at: string;
  dataset: {
    raw_rows: number;
    clean_rows: number;
    columns: number;
    missing_values: number;
    exact_duplicate_rows: number;
    duplicate_url_rows: number;
    conflicting_duplicate_groups: number;
    label_counts_raw: Record<string, number>;
    label_counts_clean: Record<string, number>;
    model_features: number;
    unique_registrable_domains: number;
    excluded_columns: Record<string, string>;
    shortcut_analysis: {
      share_https_scheme: Record<ClassName, number>;
      share_www_prefix: Record<ClassName, number>;
      share_with_path_query_or_fragment: Record<ClassName, number>;
      share_matching_template_https_www_no_path: Record<ClassName, number>;
      finding: string;
    };
    file_sha256: string;
  };
  cleaning: Record<string, unknown> & {
    rows_in: number;
    rows_out: number;
    exact_duplicate_rows_removed: number;
    near_duplicate_rows_removed_same_label: number;
    dropped_by_extractor_total: number;
    domains_with_mixed_labels: number;
  };
  splits: Record<
    string,
    {
      description: string;
      split: Record<"train" | "val" | "test", SplitPart>;
      verification: { url_overlap: Record<string, number>; domain_overlap: Record<string, number> };
    }
  >;
  selected: { chosen: string; reason: string; rule: string };
  headline: HeadlineMetrics;
  models: ModelRow[];
  limitations: string[];
}

export interface Metrics {
  n: number;
  threshold: number;
  accuracy: number;
  per_class: Record<ClassName, { precision: number; recall: number; f1: number; support: number }>;
  macro_f1: number;
  weighted_f1: number;
  roc_auc: number | null;
  pr_auc_phishing: number | null;
  brier_score: number;
  expected_calibration_error: number;
  confusion_matrix: { labels: string[]; matrix: number[][]; phishing_false_negative_rate: number; legitimate_false_positive_rate: number };
  roc_curve?: { fpr: number[]; tpr: number[] };
  pr_curve?: { recall: number[]; precision: number[] };
}

export interface ModelReport {
  display_name: string;
  best_params: Record<string, unknown>;
  tuning: { grid: { params: Record<string, unknown>; val_pr_auc_phishing: number; fit_seconds: number }[]; tuning_seconds: number };
  fit_seconds: number;
  threshold: { threshold: number; val_precision: number; val_recall: number; val_fbeta: number; beta: number };
  validation: Metrics;
  test: Metrics;
  latency: { p50_ms: number; p95_ms: number; mean_ms: number };
  model_size_bytes: number;
  native_importance: Record<string, number>;
}

export interface SliceRow {
  slice: string;
  n: number;
  phishing: number;
  legitimate: number;
  missed_phishing: number;
  false_alarms: number;
  error_rate: number;
}

export interface EvaluationReport {
  generated_at: string;
  selected: {
    chosen: string;
    reason: string;
    rule: string;
    rule_revision_note?: string;
    candidates: { model: string; val_pr_auc: number; val_phishing_recall: number; val_phishing_precision: number; val_phishing_f1: number; p50_latency_ms: number; model_size_bytes: number; eligible: boolean }[];
  };
  headline_experiment: string;
  experiments: Record<string, { description: string; models: Record<string, ModelReport> }>;
  shortcut_diagnostics: {
    template_definition: string;
    summary: string;
    test_template_rows_by_class: Record<ClassName, number>;
    rule_baseline_domain_grouped_test: Metrics;
    selected_model_on_template_slice_domain_grouped_test: Metrics;
    experiment_c_retrained_on_template_rows_only: { test_template_slice: Metrics };
  };
  feature_importance: {
    model: string;
    method: string;
    unit: string;
    sample_rows: number;
    selected_model_shap: { feature: string; label: string; mean_abs_contribution: number; mean_signed_contribution: number }[];
  };
  error_analysis: Record<string, { model: string; threshold: number; slices: SliceRow[] }>;
  manual_probe: { note: string; results: { url: string; phishing_score: number; predicted: ClassName }[] };
  limitations: string[];
}

export interface ApiErrorBody {
  error: { code: string; message: string; details?: unknown };
}
