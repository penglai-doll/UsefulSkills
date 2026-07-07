# Log Types

## v1 Verified

These have parser modules and tests in v1:

- `apache_access` / `nginx_access` / `web_access`: common or combined HTTP access logs.
- `spring_app`: Spring Boot style application logs with timestamps, level, thread, logger, and message.
- `p6spy_sql`: P6Spy SQL lines, including Chinese `SQL 语句：` messages.
- `xlsx_login`: spreadsheet exports with login fields such as `LOGIN_TIME`, `IP`, `USER_NAME`, `USER_AGENT`.
- `xlsx_operate`: spreadsheet exports with operation fields such as `OPER_DATE`, `MODULE_NAME`, `FUNC_NAME`, `OPER_DESC`.

## v1 Best-Effort

These may be inventoried and parsed with generic extraction, but reports must state limits:

- `auth_text`: Linux auth/secure style text logs.
- `firewall_text` / `waf_text`: plain-text firewall or WAF exports.
- `system_text` / `service_text`: generic OS/service logs.
- `mysqlbinlog_text`: text already exported by `mysqlbinlog`; v1 does not parse binary binlog directly.
- `generic_text`: unknown text logs with timestamps/IPs/keywords.

## Future Interface Only

Do not claim full support in v1:

- Binary MySQL/MariaDB binlog reconstruction, especially row-based events without schema.
- Windows `.evtx` and full Windows/AD/Sysmon event semantics.
- AWS/Azure/GCP/Alibaba/Tencent/Huawei cloud audit ecosystems.
- Kubernetes/container multi-source forensics.
- PCAP, memory, disk-image, or EDR proprietary formats.

## Type Mismatch Rule

If user-declared type conflicts with detected type, preserve both fields, parse with the best matching parser, and report the mismatch.
