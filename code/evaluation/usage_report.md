# Usage Report

## Final full-dataset run

| Measure | Value |
| --- | ---: |
| Requests processed | 518 |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Estimated total cost | $0.00 |
| Estimated cost per request | $0.00 |

The final run uses deterministic local parsing, identity resolution, policy evaluation, and validation. No Gemini, Groq, or other remote model call is required to produce the output, so there are no provider/model token or cost totals to report.

## Reproducibility

Run from the repository root:

```text
python code/main.py
```

The run reads only participant-facing files under `dataset/`, writes `output.csv` at the repository root, and validates the output before completing.
