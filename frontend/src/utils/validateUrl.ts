/** Light client-side check. The backend remains the authority and re-validates everything. */
export const MAX_URL_LENGTH = 2048;

export function validateUrlInput(raw: string): string | null {
  const v = raw.trim();
  if (!v) return "Enter a URL to analyze.";
  if (v.length > MAX_URL_LENGTH) return `URLs longer than ${MAX_URL_LENGTH} characters are not supported.`;
  if (/\s/.test(v)) return "The URL contains spaces or line breaks. Remove them and try again.";
  const scheme = /^([a-z][a-z0-9+.-]*):\/\//i.exec(v);
  if (scheme && !["http", "https"].includes(scheme[1].toLowerCase())) return "Only http:// and https:// URLs are supported.";
  const rest = v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/^\/\//, "");
  const host = rest.split(/[/?#]/)[0].replace(/^.*@/, "");
  if (!host || host.startsWith(":")) return "The URL needs a hostname, for example example.com.";
  return null;
}
