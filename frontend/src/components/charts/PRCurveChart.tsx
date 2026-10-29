import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ModelReport } from "../../types/api";
import { C, tooltipStyle } from "./theme";

type Kind = "pr" | "roc";

export function CurveChart({ models, kind }: { models: Record<string, ModelReport>; kind: Kind }) {
  const names = Object.keys(models);
  const series = names.map((n) => {
    const t = models[n].test;
    const pts = kind === "pr"
      ? (t.pr_curve ? t.pr_curve.recall.map((r, i) => ({ x: r, y: t.pr_curve!.precision[i] })) : [])
      : (t.roc_curve ? t.roc_curve.fpr.map((f, i) => ({ x: f, y: t.roc_curve!.tpr[i] })) : []);
    return { n, pts };
  });
  const yMin = 0.9; // both curves are zoomed to 90-100% because every model is near-perfect; axis titles say so
  // merge by index-free scatter-style lines: each series has its own data
  return (
    <figure aria-label={kind === "pr" ? "Precision-recall curves, phishing as positive class" : "ROC curves, phishing as positive class"}>
      <ResponsiveContainer width="100%" height={280}>
        <LineChart margin={{ top: 8, right: 12, bottom: 18, left: 0 }}>
          <CartesianGrid stroke={C.grid} />
          <XAxis type="number" dataKey="x" domain={kind === "pr" ? [yMin, 1] : [0, 0.1]} allowDataOverflow tickFormatter={(v) => `${(v * 100).toFixed(0)}%`}
            stroke={C.axis} tick={{ fill: C.text, fontSize: 12 }}
            label={{ value: kind === "pr" ? "Recall (phishing), axis starts at 90%" : "False positive rate (axis 0-10%)", position: "insideBottom", offset: -10, fill: C.axis, fontSize: 11 }} />
          <YAxis type="number" dataKey="y" domain={[yMin, 1]} tickFormatter={(v) => `${(v * 100).toFixed(0)}%`} stroke={C.axis} tick={{ fill: C.text, fontSize: 12 }} width={48}
            label={{ value: kind === "pr" ? "Precision (from 90%)" : "True positive rate (from 90%)", angle: -90, position: "insideLeft", fill: C.axis, fontSize: 11 }} />
          <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => `${(v * 100).toFixed(2)}%`} />
          <Legend verticalAlign="top" wrapperStyle={{ fontSize: 12 }} />
          {series.map((s) => (
            <Line key={s.n} data={s.pts} dataKey="y" name={models[s.n].display_name} stroke={C.model[s.n]} dot={false} strokeWidth={2} isAnimationActive={false} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </figure>
  );
}
