# OmniWaf

Comprehensive WAF Fingerprinting & Evasion Framework for defensive security testing.

## Overview

OmniWaf is a next-generation Web Application Firewall (WAF) analysis framework that unifies passive fingerprinting, heuristic behavioral inference, and automated evasion testing into a single pipeline. Designed for security professionals to test and validate WAF configurations.

## Why OmniWaf?

Modern WAFs are increasingly sophisticated, using ML/AI for threat detection alongside traditional signature matching. OmniWaf helps security teams:

- Identify WAF blind spots before attackers do
- Validate WAF rule effectiveness
- Test configuration against advanced bypass techniques
- Measure Security Hardening Score (SHS)

## Architecture

### Phase 1: Passive Reconnaissance
Zero-noise detection using:
- HTTP response headers (Server, X-Powered-By, X-CDN)
- Set-Cookie analysis (__cfduid, BIGipServer, etc.)
- Status code fingerprinting
- Default error page hash matching

### Phase 2: Heuristic Inference
Behavioral analysis when passive detection fails:
- Sends non-destructive payloads (SQLi, XSS, LFI, RCE)
- Measures response behavior (403, dropped connection, stripped payload)
- Calculates Security Hardening Score (SHS)
- Maps to WAF archetypes

### Phase 3: Dynamic Evasion Testing
Tests 20+ bypass techniques across 5 categories:
- Protocol-level evasion
- Parsing discrepancy exploitation
- Size manipulation
- ML/AI bypass
- Encoding techniques

### Phase 4: Unified Reporting
- Rich terminal UI with color-coded output
- JSON export for CI/CD integration
- CSV export for reporting tools

## Features

### Core Phases
- **Phase 1: Passive Reconnaissance** - Zero-noise WAF detection via HTTP headers, cookies, and response patterns
- **Phase 2: Heuristic Inference** - Behavioral analysis with Security Hardening Score (SHS)
- **Phase 3: Dynamic Evasion Testing** - Advanced bypass technique testing
- **Phase 4: Unified Reporting** - Terminal UI, JSON, and CSV output formats

### Advanced Evasion Techniques (20+)

**Protocol Level:**
- HTTP Parameter Pollution (HPP) - Split payloads across multiple parameters
- Chunked Transfer Encoding - Fragment request body into chunks
- Header Spoofing - X-Forwarded-For, X-Real-IP, X-Originating-IP rotation
- Method Override - Override HTTP method via headers
- Duplicate Headers - Send duplicate headers

**Parsing Discrepancies:**
- JSON Nested - Nest payload in deep JSON structures
- Content-Type Mismatch - Send JSON with wrong content-type
- JSON Array Payload - Send payload in JSON arrays

**Size Manipulation:**
- Padding Mode - Inject garbage data to push payload out of WAF inspection window
- Garbage Padding Prepend - Prepend large padding before payload
- Garbage Padding Postpend - Postpend large padding after payload

**ML/AI Bypass:**
- ML Junk Padding - Inject benign tokens to lower maliciousness score
- Multiple Benign Tokens - Inject multiple benign tokens around payload
- Mixed Padding - Mix benign tokens with benign JSON data

**Encoding:**
- Null Byte Injection - Prepend/scatter null bytes
- Partial URL Encoding - Partially encode URL-special characters

### Operational Features
- **Rate Limiting & Jitter** - Dynamic delays, automatic backoff on 429
- **Proxy/VPN Integration** - Rotate proxies, clear sessions on blocks
- **Configurable Categories** - Enable/disable specific evasion types
- **Stealth Progression** - Quiet to loud operation

## Installation

```bash
git clone https://github.com/CaptainBlackwave/omniprompt.git
cd omniprompt
bun install
```

## Quick Start

```bash
# Basic scan
bun run src/cli/index.ts -u https://target.com

# JSON output
bun run src/cli/index.ts -u https://target.com --json

# Save to file
bun run src/cli/index.ts -u https://target.com -o results.json
```

## Advanced Usage

```bash
# Disable specific evasion categories
bun run src/cli/index.ts -u https://target.com --no-ml --no-size

# Custom padding size (bypass inspection limits)
bun run src/cli/index.ts -u https://target.com --padding-size 16384

# Use proxies for rotation
bun run src/cli/index.ts -u https://target.com --proxies "http://proxy1:8080,http://proxy2:8080"

# Adjust rate limiting
bun run src/cli/index.ts -u https://target.com --max-rpm 20

# Skip phases for quick testing
bun run src/cli/index.ts -u https://target.com --skip-phase1 --skip-phase2
```

## Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Target URL to scan |
| `-o, --output` | Output file (json or csv) |
| `--json` | Output as JSON |
| `--csv` | Output as CSV |
| `--no-colors` | Disable colored output |
| `--skip-phase1` | Skip Phase 1 (Passive Reconnaissance) |
| `--skip-phase2` | Skip Phase 2 (Heuristic Inference) |
| `--skip-phase3` | Skip Phase 3 (Evasion Testing) |
| `--no-protocol` | Disable Protocol evasion techniques |
| `--no-parsing` | Disable Parsing evasion techniques |
| `--no-size` | Disable Size evasion techniques |
| `--no-ml` | Disable ML evasion techniques |
| `--no-encoding` | Disable Encoding evasion techniques |
| `--padding-size` | Garbage padding size in bytes (default: 8192) |
| `--proxies` | Comma-separated proxy URLs |
| `--max-rpm` | Max requests per minute (default: 10) |

## Supported WAFs (20+)

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
- Radware
- Citrix NetScaler
- Barracuda
- Trustwave
- Qualys
- StackPath
- Fastly
- Edgecast
- KeyCDN
- And more...

## Security Hardening Score (SHS)

The SHS formula calculates WAF effectiveness:

```
SHS = (Σ Wi × Bi / Σ Wi) × 100
```

Where:
- Wi = weight/severity of payload
- Bi = boolean (1 if blocked, 0 if allowed)

Score ranges:
- 0-30: Weak / Learning Mode
- 31-70: Standard / Typical Configuration
- 71-100: Strong / Strict Mode

## Output Format

### JSON
```json
{
  "target": "https://example.com",
  "waf_detected": "Cloudflare",
  "confidence": 0.98,
  "identification_method": "Passive (Signature match)",
  "hardening_score": 85,
  "successful_bypasses": ["Chunked_Transfer_Encoding", "Header_Spoofing"]
}
```

## Use Cases

- Validate WAF configuration effectiveness
- Test WAF detection capabilities
- Identify WAF blind spots
- Security hardening assessments
- Test WAF resilience against advanced bypass techniques
- CI/CD security validation pipelines

## Tech Stack

- **Language:** TypeScript
- **Runtime:** Bun
- **CLI:** Commander.js
- **UI:** Chalk + Ora

## License

MIT

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing any system. Unauthorized access to computer systems is illegal.
