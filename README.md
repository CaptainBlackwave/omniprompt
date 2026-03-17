# OmniWaf

Comprehensive WAF Fingerprinting & Evasion Framework for defensive security testing.

## Overview

OmniWaf is a next-generation Web Application Firewall (WAF) analysis framework that unifies passive fingerprinting, heuristic behavioral inference, and automated evasion testing into a single pipeline. Designed for security professionals to test and validate WAF configurations.

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

# Disable specific evasion categories
bun run src/cli/index.ts -u https://target.com --no-ml --no-size

# Custom padding size
bun run src/cli/index.ts -u https://target.com --padding-size 16384

# Use proxies
bun run src/cli/index.ts -u https://target.com --proxies "http://proxy1:8080,http://proxy2:8080"

# Rate limiting
bun run src/cli/index.ts -u https://target.com --max-rpm 20
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
- Test WAF resilience against advanced bypass techniques

## License

MIT

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing any system.
