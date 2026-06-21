# Disclaimer

AntiAiVi is an experimental antivirus/EDR prototype developed for defensive security research, education, and controlled testing.

It is not a commercial antivirus product and must not be considered a complete security solution.

## No Warranty

AntiAiVi is provided "as is", without warranty of any kind, express or implied.

The authors and contributors do not guarantee that AntiAiVi will detect, block, prevent, or remove malware, suspicious files, malicious behavior, unauthorized access, data loss, compromise, or any other security threat.

Use of AntiAiVi is entirely at your own risk.

## Experimental Project

AntiAiVi is a prototype and may contain bugs, incomplete features, false positives, false negatives, unstable behavior, or security limitations.

Some features, including real-time monitoring, behavioral analysis, Sysmon integration, VirusTotal hash lookup, and quarantine, are experimental and may not behave as expected in all environments.

Do not rely on AntiAiVi as the only protection mechanism on production systems.

## Defensive and Educational Use Only

AntiAiVi is intended only for:

* defensive security research;
* malware analysis in controlled environments;
* blue-team experimentation;
* educational purposes;
* development of detection logic;
* testing with safe samples, simulated events, or known test files such as EICAR.

Do not use AntiAiVi for unauthorized access, offensive operations, malware deployment, evasion testing against third-party systems, or any activity that violates applicable laws, contracts, policies, or terms of service.

## No Real Malware Distribution

This repository should not contain real malware samples, live payloads, credential stealers, exploit code, or harmful binaries.

Any examples included in the project should be safe, simulated, sanitized, or clearly intended for defensive testing.

Users and contributors are responsible for ensuring that any submitted files, rules, indicators, logs, or examples do not expose sensitive data or distribute harmful content.

## Privacy and Data Handling

AntiAiVi may process local files, file paths, hashes, logs, Sysmon events, command lines, process metadata, domains, IP addresses, and other system-related information.

Users are responsible for reviewing what data is scanned, logged, exported, shared, or submitted to third-party services.

When VirusTotal integration is enabled, AntiAiVi is designed to submit hashes only, not full files. However, users are responsible for verifying their configuration and understanding the privacy implications of using external services.

Do not upload or publish logs, events, file paths, API keys, credentials, private indicators, or other sensitive information unless they have been properly reviewed and sanitized.

## Quarantine Notice

AntiAiVi may move files into a quarantine directory when quarantine mode is enabled.

The current quarantine implementation is experimental. It may not encrypt quarantined files, may not preserve all metadata, and may not always support safe restoration.

Users should test quarantine behavior only in controlled environments and maintain backups of important data.

## Responsibility

The authors and contributors are not responsible for any damage, data loss, system instability, business interruption, false detection, missed detection, legal issue, privacy incident, or other consequence resulting from the use or misuse of AntiAiVi.

By using this software, you agree that you are solely responsible for your actions and for complying with all applicable laws and regulations.

## License

AntiAiVi is released under the MIT License.

See the `LICENSE` file for details.
