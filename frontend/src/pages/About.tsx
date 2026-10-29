import { ArrowRight, ArrowDown } from "lucide-react";
import { Fragment } from "react";
import { Card, CardTitle, Notice, PageHeader } from "../components/common/ui";
import { useSummary } from "../hooks/useApi";

const FLOW = [
  ["Raw URL", "Text you paste. Never opened."],
  ["URL feature extraction", "Numbers computed from the text alone."],
  ["Trained classifier", "The selected model scores the features."],
  ["Risk assessment", "Score compared to a tuned threshold."],
  ["Explanation", "Feature contributions from the model."],
];

export function AboutPage() {
  const s = useSummary();
  return (
    <>
      <PageHeader title="About & Methodology" subtitle="What PhishGuard AI does, how it was built, and where it falls short." />

      <Card>
        <CardTitle hint="No website is opened, downloaded or rendered at any point during prediction.">How a URL becomes a risk assessment</CardTitle>
        <ol className="flex flex-col items-stretch gap-2 lg:flex-row lg:items-center" aria-label="Prediction workflow">
          {FLOW.map(([t, d], i) => (
            <Fragment key={t}>
              <li className="flex-1 rounded-lg border border-line bg-ink-850 p-4">
                <p className="font-medium">{t}</p>
                <p className="mt-1 text-sm text-fog-500">{d}</p>
              </li>
              {i < FLOW.length - 1 && (<>
                <ArrowRight className="hidden h-5 w-5 shrink-0 text-teal-400 lg:block" aria-hidden />
                <ArrowDown className="mx-auto h-5 w-5 text-teal-400 lg:hidden" aria-hidden />
              </>)}
            </Fragment>
          ))}
        </ol>
      </Card>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <Card><CardTitle>Objective</CardTitle><p className="text-sm leading-relaxed text-fog-300">Help people judge whether a link looks like phishing before they open it. The tool returns a model-estimated risk score and the features that drove it. It supports a decision; it does not make one.</p></Card>
        <Card><CardTitle>URL-only analysis</CardTitle><p className="text-sm leading-relaxed text-fog-300">Every feature is computed from the URL string, using the Public Suffix List bundled with the <code className="font-mono text-xs">publicsuffix2</code> package for domain boundaries. The backend makes no request to the submitted address, so analyzing a dangerous link does not expose the server to it.</p></Card>
        <Card><CardTitle>Feature extraction</CardTitle><p className="text-sm leading-relaxed text-fog-300">One extractor module is imported by both training and the API, so the model sees identical values in both places. It counts characters, measures parts of the URL (hostname, path, query), and records signals such as IP-address hosts, punycode, embedded usernames and a short keyword list. The original dataset’s precomputed columns were not reused because they could not be reproduced from the URL.</p></Card>
        <Card><CardTitle>Preprocessing</CardTitle><p className="text-sm leading-relaxed text-fog-300">Exact duplicate URLs and same-label near-duplicates are removed, conflicting labels would be dropped, and every removal is counted. Labels stay as documented: 0 is phishing, 1 is legitimate. Learned preprocessing (scaling) is fitted on training data only.</p></Card>
        <Card><CardTitle>Model comparison</CardTitle><p className="text-sm leading-relaxed text-fog-300">Logistic Regression, Random Forest and XGBoost were trained on the same features and tuned on validation data. The final model was chosen from validation results using a documented rule, not by accuracy alone, and the decision threshold was also tuned on validation data.</p></Card>
        <Card><CardTitle>Evaluation</CardTitle><p className="text-sm leading-relaxed text-fog-300">Two experiments are reported separately: a stratified holdout and a domain-grouped split in which no registrable domain appears in more than one partition. The final test partitions were used once, after all choices were made.</p></Card>
      </div>

      <Card className="mt-6">
        <CardTitle>Limitations</CardTitle>
        <ul className="list-disc space-y-2 pl-5 text-sm text-fog-300">
          {(s.data?.limitations ?? []).map((l) => <li key={l}>{l}</li>)}
          <li>It does not guarantee a URL is safe, find every phishing attack, check a domain’s current reputation, inspect page content or scripts, or detect malware files.</li>
          <li>HTTPS is one input among many. It is not proof of legitimacy, and keywords are weak signals, not evidence.</li>
        </ul>
      </Card>

      <div className="mt-6 space-y-3">
        <Notice tone="teal" title="Responsible use">
          Treat a score as one input. Confirm the sender, type known addresses yourself, and report suspected phishing to the impersonated organization. Do not use this tool to block, accuse or take enforcement action against anyone on its own.
        </Notice>
        <Notice tone="teal" title="Privacy">
          Submitted URLs are not stored or logged by the server. The Overview page keeps a short list of recent results (domain and verdict only) in this tab’s memory and clears it when you close the tab.
        </Notice>
      </div>
    </>
  );
}
