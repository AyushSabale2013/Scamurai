import clsx from "clsx";
import { AlertTriangle, Info } from "lucide-react";
import type { ReactNode } from "react";

export function Card({ children, className, as: Tag = "section", ...rest }: { children: ReactNode; className?: string; as?: "section" | "div" | "article" } & React.HTMLAttributes<HTMLElement>) {
  return <Tag className={clsx("card card-pad", className)} {...rest}>{children}</Tag>;
}

export function CardTitle({ children, hint }: { children: ReactNode; hint?: ReactNode }) {
  return (
    <div className="mb-4">
      <h2 className="text-base font-semibold text-fog-100">{children}</h2>
      {hint && <p className="mt-1 max-w-prose text-sm text-fog-500">{hint}</p>}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-fog-300">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function Stat({ label, value, note }: { label: string; value: ReactNode; note?: ReactNode }) {
  return (
    <div className="card card-pad">
      <p className="text-sm text-fog-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums">{value}</p>
      {note && <p className="mt-1 text-xs text-fog-500">{note}</p>}
    </div>
  );
}

type Tone = "neutral" | "teal" | "amber" | "risk" | "ok";
const tones: Record<Tone, string> = {
  neutral: "border-line bg-ink-700 text-fog-300",
  teal: "border-teal-600/50 bg-teal-600/15 text-teal-300",
  amber: "border-amber-500/50 bg-amber-500/10 text-amber-300",
  risk: "border-risk-500/50 bg-risk-900 text-risk-300",
  ok: "border-ok-400/40 bg-ok-900 text-ok-400",
};

export function Badge({ tone = "neutral", children, icon }: { tone?: Tone; children: ReactNode; icon?: ReactNode }) {
  return (
    <span className={clsx("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium", tones[tone])}>
      {icon}
      {children}
    </span>
  );
}

export function Notice({ tone = "amber", title, children }: { tone?: "amber" | "teal" | "risk"; title?: string; children: ReactNode }) {
  const Icon = tone === "teal" ? Info : AlertTriangle;
  return (
    <div role="note" className={clsx("flex gap-3 rounded-lg border p-4 text-sm", tones[tone])}>
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <div className="text-fog-100">
        {title && <p className="mb-0.5 font-medium">{title}</p>}
        <div className="text-fog-300">{children}</div>
      </div>
    </div>
  );
}

export function Tip({ text, children }: { text: string; children?: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1" title={text} tabIndex={0} aria-label={text}>
      {children ?? <Info className="h-3.5 w-3.5 text-fog-500" aria-hidden />}
    </span>
  );
}

export function DataTable({ head, rows, caption, className }: { head: ReactNode[]; rows: ReactNode[][]; caption?: string; className?: string }) {
  return (
    <div className={clsx("overflow-x-auto", className)}>
      <table className="w-full min-w-[520px] text-left text-sm">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-line text-fog-500">
            {head.map((h, i) => (
              <th key={i} scope="col" className={clsx("py-2 pr-4 font-medium", i > 0 && "text-right tabular-nums")}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-line/60 last:border-0">
              {r.map((c, j) => (
                <td key={j} className={clsx("py-2 pr-4", j > 0 && "text-right tabular-nums", j === 0 && "text-fog-100")}>{c}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
