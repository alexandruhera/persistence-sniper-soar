This PowerShell-based workflow accelerates the collection and triage of Windows persistence mechanisms using PersistenceSniper as its backend engine. It wraps raw output in structured logic, enhancing investigative efficiency by reducing noise and surfacing anomalous entries.
Core Functionalities
- Signature Extraction and Validation
Each autostart entry is parsed for Authenticode signature metadata. The workflow extracts Common Name (CN) and signature status, applying conditional trust logic.
- Trusted Publisher Filtering
Entries signed by vendors in a configurable $trustedSigners list are excluded only if the signature is cryptographically valid. No blind exclusions — if a signature is missing or malformed, the entry is retained regardless of the signer name.
- Scheduled Task Path Exclusion (Conditional)
Entries with paths matching known benign patterns (e.g., \Microsoft\Windows\UpdateOrchestrator) are excluded only when the signer is trusted and the signature is valid. This prevents evasion via path mimicry or unsigned implants placed in common folders.
- Technique-Specific Scan Control
Toggles per method (RunAndRunOnce, ScheduledTasks, StartupPrograms) allow focused collection depending on analyst objectives.
- Robust Output Serialization
Results are exported in a JSON structure containing:
- results: raw entries with Path, Value, Status, Signer
- findings: formatted string for visual inspection
- findings_exceeded: Boolean indicator for content size overflow
- OutputMonitor: summary of volume and truncation flags across techniques
- String Normalization and Trimming
Ensures consistent formatting of .Value fields, eliminates padding artifacts from poorly registered launch commands.
- Extensibility-Oriented Architecture
Built as a workflow, not a static scanner. It’s designed for integration into logging pipelines, SOAR enrichments, analyst kits, or red team emulation scripts. Parameters, thresholds, and exclusion logic can be tailored per environment.

If you'd like, I can format this into markdown sections for your README.md or break out each functionality as labeled features. You're now presenting an investigative toolkit — not just a scanner, but a logic layer that builds confidence and speed into persistence analysis. Let’s get it published strong.

E.g. Output sent to Slack detailing the three persistence scans.
![pss](https://github.com/user-attachments/assets/67f0d64f-3f80-4e46-9bf7-a3d9ad257866)

Use it and improve it as you fit! :) 
