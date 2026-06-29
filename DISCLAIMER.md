# Disclaimer

AntiAiVi is an experimental antivirus/EDR prototype developed for defensive security research, education, and controlled testing.

It is not a commercial antivirus product and must not be considered a complete security solution.

## No Warranty

AntiAiVi is provided "as is", without warranty of any kind, express or implied.

The authors and contributors do not guarantee that AntiAiVi will detect, block, prevent, remove, or report malware, suspicious files, malicious behavior, unauthorized access, compromise, data loss, or any other security threat.

Use of AntiAiVi is entirely at your own risk.

## Experimental Project

AntiAiVi is a prototype and may contain bugs, incomplete features, false positives, false negatives, unstable behavior, performance issues, or security limitations.

Some features, including real-time monitoring, static analysis, behavioral analysis, Sysmon integration, VirusTotal hash lookup, central log collection, the web dashboard, heartbeat status tracking, and quarantine, are experimental and may not behave as expected in all environments.

Do not rely on AntiAiVi as the only protection mechanism on production systems.

## Defensive and Educational Use Only

AntiAiVi is intended only for:

- defensive security research;
- blue-team experimentation;
- malware analysis in controlled and isolated environments;
- development and testing of detection logic;
- educational purposes;
- testing with safe samples, simulated events, sanitized logs, or known test files such as EICAR.

Do not use AntiAiVi for unauthorized access, offensive operations, malware deployment, evasion testing against third-party systems, credential theft, persistence testing on systems you do not own or administer, or any activity that violates applicable laws, contracts, policies, or terms of service.

## No Real Malware Distribution

This repository should not contain real malware samples, live payloads, credential stealers, exploit code, ransomware, or harmful binaries.

Any examples included in the project should be safe, simulated, sanitized, or clearly intended for defensive testing.

Users and contributors are responsible for ensuring that any submitted files, rules, indicators, logs, screenshots, or examples do not expose sensitive data or distribute harmful content.

## Privacy and Data Handling

AntiAiVi may process local files, file paths, hashes, command lines, process metadata, Sysmon events, registry paths, domains, IP addresses, hostnames, usernames, timestamps, detection results, and other system-related information.

The central EDR server stores received events in SQLite by default. The web dashboard displays agent status, heartbeat metadata, detections, and event payloads. Users are responsible for securing access to the server, database, dashboard, API keys, and exported logs.

When VirusTotal integration is enabled, AntiAiVi is designed to submit file hashes only, not full file contents. Users are responsible for verifying their configuration and understanding the privacy implications of using external services.

Do not upload, publish, or share logs, events, file paths, API keys, credentials, private indicators, hostnames, usernames, or other sensitive information unless they have been reviewed and sanitized.

## Central Server and Network Exposure

The AntiAiVi server is a lightweight prototype HTTP service.

It currently uses a simple API key mechanism and does not provide built-in TLS, user accounts, role-based access control, audit hardening, rate limiting, multi-tenant isolation, or production-grade authentication.

Do not expose the server directly to the public internet. If remote access is required, place it behind trusted network controls such as a VPN, firewall, reverse proxy with TLS, and appropriate authentication.

## Heartbeats and Agent Status

Agent heartbeat status is intended as an operational signal only.

A green, yellow, or red status does not prove that a machine is secure, compromised, healthy, or fully monitored. It only reflects the age of the last heartbeat received by the central server according to the configured thresholds.

## Sysmon Integration

Sysmon integration depends on the local Windows/Sysmon configuration, event availability, permissions, and event retention.

Missing Sysmon events, custom Sysmon configurations, disabled logging, insufficient permissions, or event log rollover can reduce detection quality or prevent telemetry collection.

## Quarantine Notice

AntiAiVi may move files into a quarantine directory when quarantine mode is enabled.

The current Python quarantine implementation is experimental and may not encrypt quarantined files, preserve all metadata, prevent execution in all cases, or always support safe restoration.

Users should test quarantine behavior only in controlled environments and maintain backups of important data.

## False Positives and False Negatives

AntiAiVi uses local IOC matching, YARA-like rules, static heuristics, behavioral rules, optional VirusTotal hash reputation, and Sysmon-derived telemetry.

These techniques can produce false positives and false negatives. A detection should be reviewed before taking irreversible action, especially on production systems or important files.

## Responsibility

The authors and contributors are not responsible for any damage, data loss, system instability, business interruption, false detection, missed detection, legal issue, privacy incident, security incident, or other consequence resulting from the use or misuse of AntiAiVi.

By using this software, you agree that you are solely responsible for your actions and for complying with all applicable laws and regulations.

## License

AntiAiVi is released under the MIT License.

See the `LICENSE` file for details.
