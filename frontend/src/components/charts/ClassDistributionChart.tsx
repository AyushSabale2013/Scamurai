import { Bar, BarChart, CartesianGrid, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { num } from "../../utils/format";
import { C, tooltipStyle } from "./theme";

export function ClassDistributionChart({ counts }: { counts: Record<string, number> }) {
  const data = [
    { name: "Phishing (label 0)", value: counts["0"] ?? 0, fill: C.risk },
    { name: "Legitimate (label 1)", value: counts["1"] ?? 0, fill: C.teal },
  ];
  return (
    <figure aria-label="Number of URLs per class">
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 56, bottom: 18, left: 8 }}>
          <CartesianGrid stroke={C.grid} horizontal={false} />
          <XAxis type="number" tickFormatter={(v) => num(v)} stroke={C.axis} tick={{ fill: C.text, fontSize: 12 }}
            label={{ value: "URLs", position: "insideBottom", offset: -10, fill: C.axis, fontSize: 11 }} />
          <YAxis type="category" dataKey="name" width={150} stroke={C.axis} tick={{ fill: C.text, fontSize: 12 }} />
          <Tooltip contentStyle={tooltipStyle} formatter={(v: number) => num(v)} cursor={{ fill: "#ffffff08" }} />
          <Bar dataKey="value" radius={[0, 3, 3, 0]}>
            {data.map((d) => <Cell key={d.name} fill={d.fill} />)}
            <LabelList dataKey="value" position="right" formatter={(v: number) => num(v)} fill={C.text} fontSize={12} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </figure>
  );
}
