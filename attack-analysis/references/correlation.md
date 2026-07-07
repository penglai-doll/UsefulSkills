# Correlation

Scripts emit candidate relationships; AI decides whether a candidate becomes part of the attack chain.

## v1 Candidate Rules

Generate candidate correlations when two or more events share:

- same normalized IP within `±5 minutes` (strong) or `±30 minutes` (weak);
- same account/user within `±30 minutes`;
- same session id, request id, trace id, token fingerprint, or thread id;
- same URL path/interface name near an application error or SQL event;
- login failure followed by login success, SQL error, file upload, admin action, or sensitive endpoint access.

## Evidence Promotion

AI may promote a candidate to report timeline only when:

- timestamps are comparable or time-zone uncertainty is explicitly stated;
- raw references are available for each step;
- the causal wording matches evidence strength.

Use language like `consistent with`, `suggests`, or `confirmed by` according to evidence. Do not state identity attribution from IP ownership alone.

## Output Shape

`correlation-candidates.json` entries include:

- `correlation_id`
- `basis[]`
- `events[]`
- `window_seconds`
- `strength`: `strong` or `weak`
- `status`: `candidate`
- `notes`
