# PhishGuard AI: evaluation summary

Generated: 2026-10-29T11:23:01+00:00

Selected model: **XGBoost**. XGBoost reached validation phishing F1 0.9969 (recall 0.9951, precision 0.9988); it is within 0.001 F1 of the best model and has the lowest latency among those.

> Both experiments are reported separately. The stratified holdout lets the same domain appear in train and test and is therefore optimistic.

## Experiment: stratified

| Model | Acc | Phish P | Phish R | Phish F1 | ROC-AUC | PR-AUC | Threshold |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.9926 | 0.9896 | 0.9930 | 0.9913 | 0.99820 | 0.99867 | 0.075 |
| Random Forest | 0.9960 | 0.9945 | 0.9962 | 0.9953 | 0.99879 | 0.99905 | 0.197 |
| XGBoost | 0.9976 | 0.9983 | 0.9959 | 0.9971 | 0.99868 | 0.99900 | 0.191 |

## Experiment: domain grouped

| Model | Acc | Phish P | Phish R | Phish F1 | ROC-AUC | PR-AUC | Threshold |
|---|---|---|---|---|---|---|---|
| Logistic Regression | 0.9926 | 0.9897 | 0.9927 | 0.9912 | 0.99798 | 0.99849 | 0.084 |
| Random Forest | 0.9962 | 0.9956 | 0.9954 | 0.9955 | 0.99851 | 0.99886 | 0.250 |
| XGBoost | 0.9972 | 0.9982 | 0.9951 | 0.9966 | 0.99852 | 0.99884 | 0.229 |

## Shortcut diagnostics

100.0% of legitimate URLs in the dataset match the https://www.<host> no-path template (phishing: 1.0%), so a one-line rule that predicts 'legitimate' only for that template already reaches accuracy 0.9958 and phishing recall 0.9901 on the domain-grouped test set. Restricted to template-shaped URLs only, the selected model's phishing recall is 0.5745 (precision 0.7642); a model retrained only on those rows reaches recall 0.6028 (precision 0.6204). Headline scores overstate how well the model will do on real legitimate URLs that contain paths, which this dataset does not include.
