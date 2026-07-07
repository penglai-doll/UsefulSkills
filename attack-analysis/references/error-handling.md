# Error Handling

## Type Mismatch

Record `declared_type` and `detected_type`. Prefer detected parser if confidence is higher. Report the mismatch.

## Damaged or Garbled Lines

Skip unreadable lines, increment `bad_line_count`, and preserve a small sample if safe. Do not abort the whole case.

## Timestamp Failures

Keep the event with `timestamp_status=unknown`. Do not use it for strict chronological ordering unless AI can infer context and states that limitation.

## Time Zone Ambiguity

Use `default_timezone` only as a fallback. Prefer per-file `timezone`. Mark `time_parse_status` as `explicit`, `inferred`, or `unknown`.

## IP Variants

Normalize `1.2.3.4:54321`, `X-Forwarded-For`, bracketed IPv6, and comma-separated proxy chains into `actor_ip_normalized`, `actor_port`, and optional `ip_chain`.

## Compression and Encoding Failures

Record failure in inventory and continue other files. Use replacement decoding for text when necessary, and report parse quality.
