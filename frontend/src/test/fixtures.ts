export const prediction = {
  predicted_class: 0, class_name: "phishing", label: "Potential phishing URL", phishing_score: 0.987, threshold: 0.31,
  model_version: "1.0.0-test", features: { url_length: 52, hostname_length: 19, is_https: 0 },
  url_parts: { scheme: "http", subdomain: "", registered_domain: "secure-login.xyz", port: null, path: "/verify/account.php", query: "id=7", fragment: "", scheme_assumed: false },
  explanation: [{ feature: "is_https", label: "Uses HTTPS", description: "d", value: 0, contribution: 1.4, direction: "toward_phishing", training_percentile: 40 }],
  explanation_method: "SHAP TreeExplainer", explanation_unit: "log-odds", notes: [], disclaimer: "Machine learning predictions are estimates.",
};

export const summary = {
  generated_at: "2026-01-01", dataset: { raw_rows: 1000, clean_rows: 990, columns: 56, missing_values: 0, exact_duplicate_rows: 0, duplicate_url_rows: 5, conflicting_duplicate_groups: 0,
    label_counts_raw: { "0": 400, "1": 600 }, label_counts_clean: { "0": 395, "1": 595 }, model_features: 39, unique_registrable_domains: 900, excluded_columns: {},
    shortcut_analysis: { share_https_scheme: { phishing: 0.5, legitimate: 1 }, share_www_prefix: { phishing: 0.4, legitimate: 1 }, share_with_path_query_or_fragment: { phishing: 0.3, legitimate: 0 },
      share_matching_template_https_www_no_path: { phishing: 0.01, legitimate: 1 }, finding: "f" }, file_sha256: "abc" },
  cleaning: { rows_in: 1000, rows_out: 990, exact_duplicate_rows_removed: 5, near_duplicate_rows_removed_same_label: 5, dropped_by_extractor_total: 0, domains_with_mixed_labels: 0 },
  splits: {}, selected: { chosen: "xgboost", reason: "r", rule: "r" },
  headline: { experiment: "domain_grouped", model: "xgboost", display_name: "XGBoost", phishing_recall: 0.995, phishing_precision: 0.998, phishing_f1: 0.996, pr_auc: 0.9988, accuracy: 0.997, latency_p50_ms: 1.9, threshold: 0.31 },
  models: [], limitations: ["URL-only."],
};
