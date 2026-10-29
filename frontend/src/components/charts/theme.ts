export const C = {
  grid: "#24304d", axis: "#8493ad", text: "#b4bfd3", tipBg: "#0f1729",
  teal: "#3cc4b5", periwinkle: "#8ea4d0", sand: "#d9c9a3", risk: "#ef6b6b", amber: "#e6a93b",
  model: { logistic_regression: "#8ea4d0", random_forest: "#e6a93b", xgboost: "#3cc4b5" } as Record<string, string>,
};
export const tooltipStyle = { background: C.tipBg, border: `1px solid ${C.grid}`, borderRadius: 8, color: "#e8edf6", fontSize: 12 };
