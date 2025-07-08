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

E.g. Output sent to Slack detailing the three persistence scans.
![pss](https://github.com/user-attachments/assets/67f0d64f-3f80-4e46-9bf7-a3d9ad257866)
![image](https://github.com/user-attachments/assets/09796cef-e208-4c0c-b8a2-0b9c9af41a96)

![pss3x](https://github.com/user-attachments/assets/e1915116-32e2-48a5-9785-5626e56ded4d)
![pss3xc](https://github.com/user-attachments/assets/832afc57-7f70-4172-a43d-9c8d4548bc3e)

Use it and improve it as you fit! :) 
