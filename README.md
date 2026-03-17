# OmniWaf

Comprehensive WAF Fingerprinting & Evasion Framework for defensive security testing.

## Overview

OmniWaf is a next-generation Web Application Firewall (WAF) analysis framework that unifies passive fingerprinting, heuristic behavioral inference, and automated evasion testing into a single pipeline. Designed for security professionals to test and validate WAF configurations.

## Features

- **Phase 1: Passive Reconnaissance** - Zero-noise WAF detection via HTTP headers, cookies, and response patterns
- **Phase 2: Heuristic Inference** - Behavioral analysis with Security Hardening Score (SHS)
- **Phase 3: Dynamic Evasion Testing** - Tamper script testing for bypass validation
- **Phase 4: Unified Reporting** - Terminal UI, JSON, and CSV output formats

## Installation

```bash
git clone https://github.com/CaptainBlackwave/omniprompt.git
cd omniprompt
bun install
```

## Usage

```bash
# Basic scan
bun run src/cli/index.ts -u https://target.com

# JSON output
bun run src/cli/index.ts -u https://target.com --json

# Save to file
bun run src/cli/index.ts -u https://target.com -o results.json

# CSV output
bun run src/cli/index.ts -u https://target.com --csv
```

## Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL to scan |
| `-o, --output` | Output file (json or csv) |
| `--json` | Output as JSON |
| `--csv` | Output as CSV |
| `--no-colors` | Disable colored output |

## Supported WAFs

- Cloudflare
- AWS WAF
- ModSecurity
- F5 BIG-IP ASM
- Imperva Incapsula
- Akamai
- Sucuri
- Wordfence
- FortiWeb
- Palo Alto Networks
- And 10+ more...

## Use Cases

- Validate WAF configuration effectiveness
- Test WAF detection capabilities
- Identify WAF blind spots
- Security hardening assessments

## License

MIT

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing any system.
