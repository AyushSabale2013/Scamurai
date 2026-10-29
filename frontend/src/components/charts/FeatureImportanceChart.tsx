import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { C, tooltipStyle } from "./theme";

export function FeatureImportanceChart({ rows, unit, top = 12 }: { rows: { label: string; mean_abs_contribution: number }[]; unit: string; top?: number }) {
  const data = rows.slice(0, top).map((r) => ({ name: r.label, value: r.mean_abs_contribution }));
  return (
    <figure aria-label="Mean absolute model contribution per feature">
      <ResponsiveContainer width="100%" height={Math.max(220, data.length * 26 + 40)}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 22, left: 8 }}>
          <CartesianGrid stroke={C.grid} horizontal={false} />
          <XAxis type="number" stroke={C.axis} tick={{ fill: C.text, fontSize: 12 }}
            label={{ value: `Mean |contribution| (${unit})`, position: "insideBottom", offset: -12, fill: C.axis, fontSize: 11 }} />
          <YAxis type="category" dataKey="name" width={150} stroke={C.axis} tick={{ fill: C.text, fontSize: 12 }} interval={0} />
          <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => v.toFixed(3)} cursor={{ fill: "#ffffff08" }} />
          <Bar dataKey="value" fill={C.teal} radius={[0, 3, 3, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </figure>
  );
}
