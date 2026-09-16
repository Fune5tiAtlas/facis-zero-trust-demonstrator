# Helm charts

Helm charts for the demonstrator. The umbrella chart installs a complete zone: management and data
planes in separate namespaces, baseline deny network policies, and installation ordered so that
workload identity exists before any workload starts.

Each chart documents its values alongside it. Nothing here should require a manual step after
`helm install` — if it does, that is a defect in the chart.
