import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ModelRow } from "../../types/api";
import { pct } from "../../utils/format";
import { C, tooltipStyle } from "./theme";

export function ModelComparisonChart({ rows, experiment }: { rows: ModelRow[]; experiment: string }) {
  const data = rows.filter((r) => r.experiment === experiment).map((r) => ({
    name: r.display_name, Precision: r.phishing_precision, Recall: r.phishing_recall, "F1-score": r.phishing_f1,
  }));
  const min = Math.min(...data.flatMap((d) => [d.Precision, d.Recall, d["F1-score"]]));
  const floor = Math.max(0, Math.floor((min - 0.005) * 100) / 100);
  return (
    <figure aria-label="Phishing-class precision, recall and F1 for each model on the test set">
      <ResponsiveContainer width="100%" height={280}>
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 4, left: 0 }}>
          <CartesianGrid stroke={C.grid} vertical={false} />
          <XAxis dataKey="name" stroke={C.axis} tick={{ fill: C.text, fontSize: 12 }} />
          <YAxis domain={[floor, 1]} tickFormatter={(v) => `${(v * 100).toFixed(1)}%`} stroke={C.axis} tick={{ fill: C.text, fontSize: 12 }} width={56}
            label={{ value: "Score (phishing class, test)", angle: -90, position: "insideLeft", fill: C.axis, fontSize: 11, dx: -2 }} />
          <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => pct(v, 3)} cursor={{ fill: "#ffffff08" }} />
          <Legend wrapperStyle={{ fontSize: 12, color: C.text }} />
          <Bar dataKey="Precision" fill={C.teal} radius={[3, 3, 0, 0]} />
          <Bar dataKey="Recall" fill={C.periwinkle} radius={[3, 3, 0, 0]} />
          <Bar dataKey="F1-score" fill={C.sand} radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </figure>
  );
}
