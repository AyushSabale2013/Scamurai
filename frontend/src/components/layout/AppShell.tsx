import clsx from "clsx";
import { BookOpen, Database, FlaskConical, LayoutDashboard, ListChecks, Menu, ScanSearch, ShieldCheck, X } from "lucide-react";
import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useHealth } from "../../hooks/useApi";
import { Badge } from "../common/ui";

export const NAV = [
  { to: "/", label: "Overview", title: "Security Overview", icon: LayoutDashboard },
  { to: "/analyzer", label: "URL Analyzer", title: "URL Analyzer", icon: ScanSearch },
  { to: "/batch", label: "Batch Analysis", title: "Batch Analysis", icon: ListChecks },
  { to: "/model-lab", label: "Model Lab", title: "Model Lab", icon: FlaskConical },
  { to: "/dataset", label: "Dataset Explorer", title: "Dataset Explorer", icon: Database },
  { to: "/about", label: "About & Methodology", title: "About & Methodology", icon: BookOpen },
] as const;

function BackendStatus() {
  const { data, isError, isLoading } = useHealth();
  if (isLoading) return <Badge>Checking API…</Badge>;
  if (isError) return <Badge tone="risk">API unreachable</Badge>;
  if (!data?.model_loaded) return <Badge tone="amber">API up, model not loaded</Badge>;
  return <Badge tone="ok">API healthy</Badge>;
}

function Nav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav aria-label="Main" className="flex flex-col gap-1">
      {NAV.map(({ to, label, icon: Icon }) => (
        <NavLink
          key={to}
          to={to}
          end={to === "/"}
          onClick={onNavigate}
          className={({ isActive }) =>
            clsx("flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors",
              isActive ? "bg-teal-600/15 font-medium text-teal-300" : "text-fog-300 hover:bg-ink-700 hover:text-fog-100")
          }
        >
          <Icon className="h-4 w-4" aria-hidden />
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-2.5 px-3">
      <ShieldCheck className="h-6 w-6 text-teal-400" aria-hidden />
      <span className="text-lg font-semibold tracking-tight">Scamurai</span>
    </div>
  );
}

export function AppShell() {
  const [open, setOpen] = useState(false);
  const { pathname } = useLocation();
  const { data: health } = useHealth();
  const title = NAV.find((n) => (n.to === "/" ? pathname === "/" : pathname.startsWith(n.to)))?.title ?? "Scamurai";

  useEffect(() => { document.title = `${title} · Scamurai`; }, [title]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  return (
    <div className="min-h-screen bg-ink-900">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-teal-500 focus:px-3 focus:py-2 focus:text-ink-950">Skip to content</a>

      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-line bg-ink-850 py-5 lg:flex">
        <Brand />
        <div className="mt-8 flex-1 px-3"><Nav /></div>
        <div className="space-y-2 px-6 text-xs text-fog-500">
          <BackendStatus />
          <p>URLs are analyzed as text. No site is ever visited.</p>
        </div>
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <button type="button" aria-label="Close menu" className="absolute inset-0 bg-ink-950/70" onClick={() => setOpen(false)} />
          <div className="absolute inset-y-0 left-0 flex w-64 flex-col bg-ink-850 py-5">
            <div className="flex items-center justify-between pr-3">
              <Brand />
              <button type="button" className="btn-ghost p-2" aria-label="Close menu" onClick={() => setOpen(false)}><X className="h-5 w-5" /></button>
            </div>
            <div className="mt-6 flex-1 px-3"><Nav onNavigate={() => setOpen(false)} /></div>
            <div className="px-6"><BackendStatus /></div>
          </div>
        </div>
      )}

      <div className="lg:pl-60">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-line bg-ink-900/95 px-4 py-3 backdrop-blur sm:px-8">
          <button type="button" className="btn-ghost p-2 lg:hidden" aria-label="Open menu" aria-expanded={open} onClick={() => setOpen(true)}>
            <Menu className="h-5 w-5" />
          </button>
          <p className="flex-1 truncate text-sm font-medium text-fog-300">{title}</p>
          <div className="hidden items-center gap-2 sm:flex">
            <Badge tone={health?.model_loaded ? "teal" : "neutral"}>
              {health?.model_loaded ? `Model ${health.model_version}` : "Model not loaded"}
            </Badge>
          </div>
          <div className="lg:hidden"><BackendStatus /></div>
        </header>
        <main id="main" className="mx-auto max-w-7xl px-4 py-8 sm:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
