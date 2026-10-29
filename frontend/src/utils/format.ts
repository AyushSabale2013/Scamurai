export const pct = (v: number | null | undefined, digits = 2): string =>
  v == null || Number.isNaN(v) ? "n/a" : `${(v * 100).toFixed(digits)}%`;

export const num = (v: number | null | undefined, digits = 0): string =>
  v == null || Number.isNaN(v) ? "n/a" : v.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: digits });

export const ms = (v: number | null | undefined): string => (v == null ? "n/a" : `${v < 10 ? v.toFixed(2) : v.toFixed(1)} ms`);

export const bytes = (v: number | null | undefined): string => {
  if (v == null) return "n/a";
  if (v < 1024) return `${v} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / 1024 / 1024).toFixed(1)} MB`;
};

export const secs = (v: number | null | undefined): string => (v == null ? "n/a" : v < 60 ? `${v.toFixed(1)} s` : `${(v / 60).toFixed(1)} min`);

export const experimentLabel = (k: string): string => (k === "domain_grouped" ? "Domain-grouped" : k === "stratified" ? "Stratified" : k);
