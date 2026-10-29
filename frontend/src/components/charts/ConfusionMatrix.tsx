import clsx from "clsx";
import type { Metrics } from "../../types/api";
import { num, pct } from "../../utils/format";

export function ConfusionMatrix({ metrics, title }: { metrics: Metrics; title: string }) {
  const m = metrics.confusion_matrix.matrix;
  const labels = ["Phishing", "Legitimate"];
  return (
    <figure>
      <figcaption className="mb-2 text-sm font-medium">{title}</figcaption>
      <table className="w-full table-fixed border-separate border-spacing-1 text-center text-sm">
        <caption className="sr-only">Confusion matrix: rows are actual class, columns are predicted class</caption>
        <thead>
          <tr>
            <td />
            {labels.map((l) => <th key={l} scope="col" className="pb-1 text-xs font-medium text-fog-500">Predicted {l.toLowerCase()}</th>)}
          </tr>
        </thead>
        <tbody>
          {m.map((row, i) => {
            const total = row.reduce((a, b) => a + b, 0) || 1;
            return (
              <tr key={i}>
                <th scope="row" className="pr-1 text-left text-xs font-medium text-fog-500">Actual {labels[i].toLowerCase()}</th>
                {row.map((v, j) => {
                  const correct = i === j;
                  const share = v / total;
                  return (
                    <td key={j} className={clsx("rounded-md border px-2 py-3", correct ? "border-teal-600/50 bg-teal-600/15" : v > 0 ? "border-risk-500/50 bg-risk-900" : "border-line bg-ink-850")}>
                      <div className="font-semibold tabular-nums">{num(v)}</div>
                      <div className="text-xs text-fog-500">{pct(share, 2)} of row</div>
                      <div className="sr-only">{correct ? "correct" : "error"}</div>
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </figure>
  );
}
