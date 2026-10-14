# Datasets and Samples Directory

This directory contains security telemetry samples, synthetic evaluation scenarios, and local knowledge corpora.

## Included Files
- `samples/openssh_sample.log`: Realistic OpenSSH authentication log containing:
  - Repeated brute-force password guessing from `187.141.143.180` targeting `admin`, `guest`, `oracle`, and `root`.
  - Failed-then-successful login compromise on account `analyst` from `203.0.113.45`.
  - Legitimate administrative public-key login and session handling for `fztu`.
- `samples/auth_events.json`: Structured JSON authentication events with repeated failed logins.
- `samples/auth_events.csv`: Standard CSV authentication log with external brute-force activity.
- `test_cases/`: Labeled synthetic benchmark scenarios used for regression testing and evaluation.
