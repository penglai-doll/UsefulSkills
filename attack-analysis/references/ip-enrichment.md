# IP Enrichment and Privacy

## Default Policy

Network assist is enabled by default for public enrichment. If unavailable, set `network_status` to `failed` or `offline_fallback` and continue local analysis.

Default enrichment targets:

- IP geolocation, ASN, ISP/operator, cloud/IDC ownership.
- Domain ownership and public DNS context.
- Public CVE/product documentation.
- Scanner, crawler, and User-Agent signatures.
- Public attack-pattern references.

## Privacy Boundaries

Allowed external query data by default:

- source IPs;
- domains;
- ASN targets;
- product/CVE names;
- public keywords;
- short User-Agent fragments.

Do not send by default:

- complete logs;
- request bodies;
- tokens, cookies, sessions, passwords, API keys;
- private account identifiers;
- internal business parameters;
- database rows or full SQL results;
- complete sensitive URLs with query secrets.

## Tooling

Do not install tools, download GeoIP databases, or configure external API keys without asking the user separately. If enrichment is partial, state the source and limitation in the report.
