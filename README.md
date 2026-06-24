# Text-Log Sanitization

Before dumping logs or long text files into online tools, sanitize them locally so you do not leak company names, IP addresses, hostnames, usernames, domains, URLs, hashes, GUIDs, MAC addresses, or email addresses.

This repository provides two offline sanitizers:

- `scripts/log_sanitizer.py` for Python 3.
- `scripts/Log-Sanitizer.ps1` for PowerShell.

Both scripts keep the original log context intact while replacing selected sensitive values with stable fake values. Stable replacement means the same original value maps to the same fake value throughout the output file.

## Python usage

Preview findings interactively and choose which categories to randomize:

```bash
python3 scripts/log_sanitizer.py input.log
```

Write to a custom output path:

```bash
python3 scripts/log_sanitizer.py input.log --output sanitized.log
```

Sanitize all detected categories without prompts and save the replacement map:

```bash
python3 scripts/log_sanitizer.py input.log --categories all --save-map
```

Sanitize only specific categories:

```bash
python3 scripts/log_sanitizer.py input.log --categories ipv4,domain,email
```

## PowerShell usage

Preview findings interactively and choose which categories to randomize:

```powershell
pwsh ./scripts/Log-Sanitizer.ps1 ./input.log
```

Write to a custom output path:

```powershell
pwsh ./scripts/Log-Sanitizer.ps1 ./input.log -OutputPath ./sanitized.log
```

Sanitize all detected categories without prompts and save the replacement map:

```powershell
pwsh ./scripts/Log-Sanitizer.ps1 ./input.log -Categories all -SaveMap
```

Sanitize only specific categories:

```powershell
pwsh ./scripts/Log-Sanitizer.ps1 ./input.log -Categories ipv4,domain,email
```

## Detected categories

The scripts detect and can replace:

- IPv4 and IPv6 addresses.
- URLs and domain names.
- Email addresses and UPN-style usernames.
- Windows `DOMAIN\username` identities.
- Common hostname formats such as `SRV-APP01` or `DESKTOP-ABC123`.
- MAC addresses.
- GUIDs.
- 32- to 64-character hexadecimal hashes.

## Notes

These scripts are heuristic hygiene tools, not formal data-loss-prevention products. Review sanitized output before sharing it externally, especially if your logs contain unusual identifiers, proprietary naming conventions, or secrets with formats not listed above.
