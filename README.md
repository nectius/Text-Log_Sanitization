# Log Hygiene Sanitizer

Log Hygiene Sanitizer is a static Cloudflare Pages app that sanitizes logs entirely in the browser. It is designed for safely preparing logs before sharing them with support teams, ticketing systems, chat tools, or AI assistants.

## Privacy and deployment model

- Static frontend only.
- No backend.
- No Cloudflare Worker.
- No Pages Function.
- No external API calls.
- Sanitization runs locally in the browser.
- The Cloudflare Pages `_headers` file sets a strict Content Security Policy, including `connect-src 'none'`, so browser network connections are blocked by policy.

## What it detects

The browser app follows the same heuristic categories as the original Python and PowerShell sanitizers in `scripts/`:

- URLs.
- Email addresses.
- Windows `DOMAIN\username` identities.
- IPv4 and IPv6 addresses.
- MAC addresses.
- Domain names.
- Common hostnames such as `SRV-APP01` or `DESKTOP-ABC123`.
- GUIDs.
- 32- to 64-character hexadecimal hashes.

Detected values are replaced with stable fake values, meaning the same original value maps to the same replacement throughout the output.

## Local development

```bash
npm run build
```

The build command validates `app.js`, verifies the required static files exist, and copies the Cloudflare Pages assets to `dist/`.

You can also open `index.html` directly in a browser for local testing.

## Cloudflare Pages settings

Use these settings when creating the Pages project:

- Framework preset: `None`.
- Build command: `npm run build`.
- Build output directory: `dist`.
- Root directory: repository root.
- Environment variables: none required.

## Original CLI scripts

The repository still includes the original offline CLI sanitizers:

- `scripts/log_sanitizer.py` for Python 3.
- `scripts/Log-Sanitizer.ps1` for PowerShell.

Those scripts were inspected while creating the browser version and were not modified.
