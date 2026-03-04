# Security Assessment — Private AI-Powered Smart Contract Auditing Tool

**Engagement type:** Full-stack security assessment + smart contract tooling audit
**Target:** Private AI tool (Web3 / smart contract security domain) — client name withheld by agreement
**Date:** March 2026
**Scope:** Web application, API layer, network exposure, smart contract static analysis, benchmark validation

---

## Engagement Overview

The client is building an AI-powered tool in the smart contract security space. They requested an independent review covering the web application security posture, infrastructure configuration, and the accuracy of the tool's core detection capabilities against a curated benchmark of 30 Solidity contracts across three difficulty tiers.

This document is a sanitized version of the full report, published with client permission for portfolio purposes. All proprietary architecture details, contract names, addresses, and competitive implementation specifics have been removed.

---

## Methodology

| Phase | Method | Tool |
|---|---|---|
| Static code review | Manual source analysis | — |
| Web pentesting | Passive scan + spider | OWASP ZAP 2.17.0 |
| Network scan | Port + service enumeration | Nmap 7.94 |
| Authenticated API testing | Manual probe with live session | PowerShell / curl |
| Smart contract static analysis | 30-contract full run | Slither 0.11.5 |
| Exploit validation | Test harness execution | Forge (Foundry) 1.4.4 |
| Benchmark cross-reference | Ground truth comparison across 3 tiers | Manual |
| Architecture review | Design pattern analysis | — |

---

## Risk Summary

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 7 |
| Low | 5 |
| Informational | 4 |

---

## Key Findings

### Critical — Database Port Exposed on Host Network

The containerized database was mapped directly to the host network interface via the orchestration configuration. On a cloud deployment with a public IP and no firewall rule, this exposes the database to the internet with no application-layer barrier. The internal services that consume the database do not require host-level port exposure — they communicate over the container network.

**Fix:** Remove the host port mapping from the database service. Internal services connect via the container network hostname.

---

### High — Session Cookies Lack Secure Flag (Live Confirmed)

Captured directly from sign-in response headers during live authenticated testing:

```
session_token:  HttpOnly=true   Secure=false   SameSite=Lax
session_data:   HttpOnly=true   Secure=false   SameSite=Lax
```

`HttpOnly` is correctly set, which prevents JavaScript access. However, the missing `Secure` flag means session tokens transmit in plaintext over any non-HTTPS connection — a misconfigured staging environment, internal network, or proxy chain without TLS termination would expose active sessions on the wire.

**Fix:** Set `Secure: true` on all session cookies. Enforce HTTPS across all deployment environments.

---

### High — No TLS Enforcement at Application Layer

The application had no HTTP-to-HTTPS redirect and no `Strict-Transport-Security` header. A deployment behind a misconfigured reverse proxy (proxy in HTTP mode, staging without TLS) silently exposes session tokens and API keys in cleartext with no application-level warning.

---

### Medium — Admin Endpoint Accessible to Any Authenticated User (Live Confirmed)

A system administration endpoint returned `HTTP 200` with operational queue data when called using a regular user session created during testing. The route only checked that the user was authenticated — it did not check whether the user held an administrative role. In a multi-tenant deployment, this endpoint's response includes recent failure records that could reference other users' job identifiers and internal error messages.

**Fix:** Implement role-based access control. Return `403 Forbidden` for non-administrative sessions on all admin routes.

---

### Medium — Content Security Policy Contains `unsafe-inline`

```
Content-Security-Policy:
  script-src 'self' 'unsafe-inline' ...
  style-src  'self' 'unsafe-inline' ...
  connect-src https: ...
```

`unsafe-inline` in `script-src` negates CSP as an XSS mitigation. Any stored or reflected XSS in user-controlled content (which in this context includes AI-generated findings displayed to the user) would execute without CSP interference. The `connect-src https:` wildcard also permits exfiltration to any HTTPS endpoint.

**Fix:** Replace `unsafe-inline` with a per-request nonce. Narrow `connect-src` to specific required domains.

---

### Medium — API Key Scope Not Enforced

The application supported API key authentication as an alternative to session cookies but did not implement read/write/admin scope differentiation. Any issued key granted full access to all operations. A leaked read-only integration key would carry the same write privileges as a key intended for full access.

---

### Medium — Input Validation Bypass via Language Field

The submission endpoint enforced thorough content validation for the primary supported language. However, setting the `language` parameter to an unsupported value bypassed all structural validation gates — byte limits, character limits, content marker checks — and passed the raw payload directly into the processing pipeline. Setting `language: "vyper"` or any other value reproduced this bypass.

**Fix:** Restrict the `language` field to an allowlist enum at the schema validation layer.

---

### Additional Findings (Summary)

| ID | Severity | Title |
|---|---|---|
| M-4 | Medium | Origin validation falls back to Referer header on state-mutating routes |
| M-5 | Medium | File name field not sanitized against path traversal characters |
| M-6 | Medium | Container image referenced by mutable tag instead of digest |
| M-7 | Medium | In-process job queue has no crash recovery or dead-letter queue |
| L-1 | Low | No secrets management solution (rotation policy, vault integration) |
| L-2 | Low | No structured application-level audit log for privileged operations |
| L-3 | Low | External address field has no format validation before reaching integrations |
| L-4 | Low | No per-job LLM token budget cap |
| L-5 | Low | Dependency vulnerability scan not gated in CI pipeline |
| I-1 | Info | Account enumeration not possible (responses are identical — correct behavior) |
| I-2 | Info | Technology fingerprinting header present |
| I-3 | Info | Exploit test harness has Solidity 0.8.x arithmetic incompatibility |
| I-4 | Info | Test coverage reporting not configured |

---

## Web Application Testing

**Tool:** OWASP ZAP 2.17.0 — passive scan + unauthenticated spider
**Result:** 0 High findings, 3 Medium (all CSP-related), 1 Low, 1 Informational

39% of ZAP-probed URLs returned 4xx. The application correctly rejected all unauthenticated probe traffic. No injection points found, no data leaks in responses.

Manual authenticated testing was performed using a test account registered during the engagement. Key results:

```
GET  /api/audits (unauthenticated)       → 401  correct
POST /api/submit (no CSRF token)         → 403  correct — CSRF protection confirmed
POST /api/auth/keys (no Origin header)   → 403  correct — origin validation confirmed
GET  /api/admin/queue (regular user)     → 200  FINDING — no role check on admin route
GET  /api/item/<nonexistent-id>          → 404  correct — no IDOR, no enumeration

Account enumeration test:
  Unknown email + any password           → 401  identical response
  Known email + wrong password           → 401  identical response
  Not vulnerable.
```

---

## Network Exposure (Nmap)

```
PORT     STATE  SERVICE      FINDING
3000/tcp open   http         Application — expected
5432/tcp open   postgresql   Database exposed on host — CRITICAL FINDING
135/tcp  open   msrpc        Windows host — not application
445/tcp  open   netbios-ssn  Windows host — not application
```

---

## Smart Contract Static Analysis — Slither vs Target Tool

One component of the engagement was validating the detection capabilities of the client's tool against a benchmark of 30 intentionally vulnerable Solidity contracts, spanning three difficulty tiers:

- **Tier 1 (10 contracts):** Synthetic, textbook vulnerability patterns with one clean negative-test contract
- **Tier 2 (10 contracts):** Simplified recreations of real historical DeFi exploits
- **Tier 3 (10 contracts):** Patterns derived from public audit reports

All 30 contracts were also run through Slither 0.11.5 independently to produce a side-by-side comparison.

### Aggregate Results

| Metric | Slither 0.11.5 | Client Tool (blind run) |
|---|---|---|
| Total expected findings | 42 | 42 |
| True detections | ~7–8 (~18%) | 33 (78.6%) |
| Severity accuracy | Not scored | 22/33 (66.7%) |
| False positive volume | Very high (boilerplate warnings on every contract) | 21/54 submitted (38.9%) |
| DeFi-specific classes (oracle, flash-loan, governance, price-manip) | None | Core strength |
| Shared misses | 3 | 3 |

### Per-Tier Detection Rates

| Tier | Expected Findings | Client Tool | Slither |
|---|---|---|---|
| Tier 1 (Synthetic) | 12 | 11/12 (91.7%) | ~3/12 |
| Tier 2 (Real exploit patterns) | 20 | 14/20 (70.0%) | ~3/20 |
| Tier 3 (Audit-derived) | 10 | 8/10 (80.0%) | ~1.5/10 |

### Slither Coverage by Vulnerability Class

| Class | Slither | Client Tool |
|---|---|---|
| Reentrancy | Strong | Strong |
| Unchecked ERC20 return | Strong | Strong |
| Uninitialized storage | Good | Good |
| Delegatecall (semantic) | Partial | Strong |
| Oracle manipulation | None | Strong |
| Price / flash-loan manipulation | None | Strong |
| Governance (timelock, snapshot) | None | Strong |
| Signature verification (replay, domain) | None | Strong |
| Precision loss / rounding | None | Strong |
| Denial of service (gas exhaustion) | None | Strong |

### Key Observation: Slither False Positive Problem

Slither generates `solc-version`, `naming-convention`, `constable-states`, and `immutable-states` findings on every contract regardless of actual vulnerability content. On the Tier 2 contracts, this produced 4–8 findings per contract of which 0–1 were relevant. In a production triage workflow, this noise-to-signal ratio would bury real findings. The client tool does not suffer from this problem to the same degree, though its 38.9% precision rate indicates room for improvement.

### The Three Shared Misses

Both tools missed the same three contracts (one from each tier cluster). In all three cases, the vulnerability cannot be determined from Solidity source code alone — it requires external context:

- One contract requires knowing that AMM spot prices are manipulable within a single transaction via flash loans
- One contract requires knowing that a particular exchange rate formula is derived from real-time storage values (not snapshots) and is therefore flash-manipulable
- One contract requires knowing that the integrated price oracle returns 8-decimal values, making the hardcoded scaling factor incorrect

These are legitimate limitations of source-only analysis. Neither static analysis tools nor LLM-based analysis can reliably catch this class of vulnerability without integration documentation or differential fuzzing against a reference implementation.

---

## Platform Gaps (Non-Security)

These are capability gaps relevant to the question of what the tool does well and where it falls short relative to a professional audit engagement.

| Gap | Detail |
|---|---|
| Single-file input only | Real-world audits involve multi-file projects with imports and remappings. No ZIP, no repo ingestion. |
| No static analysis pre-pass | Running Slither before the AI pipeline would reduce token cost and surface easy findings cheaply |
| No exploit/patch execution | Detection works. Proving exploitability via Foundry harness is scaffolded but not wired into the pipeline |
| Severity calibration | 33% of matched findings had incorrect severity. Oracle and governance findings consistently under-scored |
| No feedback loop | Confirmed/denied findings from real use cannot flow back to improve detection confidence |
| No WAF / DDoS protection | Application-level rate limiting only; SSE streaming endpoint is a long-held-connection risk at scale |

---

## Recommendations Summary

### Immediate (before any public deployment)

1. Remove database host port mapping
2. Set `Secure` flag on all session cookies
3. Add HTTPS enforcement + HSTS header
4. Add role check on admin route
5. Disable technology fingerprinting header

### Before GA

6. Replace `unsafe-inline` with nonce-based CSP
7. Add scope (read/write/admin) to API keys
8. Hard-reject state-mutating requests with absent Origin header
9. Sanitize file name field to basename + allowlist
10. Lock language field to enum allowlist
11. Pin container image to digest
12. Replace in-process job queue with Postgres-backed persistent queue
13. Add input format validation for external address fields

### Roadmap

14. Multi-file / repo ingestion support
15. Static analysis pre-pass feeding AI context
16. Fix exploit harness for Solidity 0.8.x checked arithmetic
17. Wire exploit/patch harness execution into pipeline
18. Severity calibration uplift for oracle / governance / precision-loss classes
19. Confirmed/denied feedback loop to update detection confidence
20. False positive rate dashboard by vulnerability category

---

## Tooling Notes

**Slither on Windows:** `solc-select` attempts to write to the Python installation directory on Windows, causing a permission error. Workaround: set `VIRTUAL_ENV` to a user-writable path before running `solc-select install`. This is stable and reproducible.

**Forge/Foundry:** Fully functional. The exploit harness failure on Tier 1 reentrancy contract is a test scaffolding issue — the harness was written assuming pre-0.8.x unchecked arithmetic. The vulnerability in the target contract is real. The patch harness passes correctly.

---

*Client name withheld by mutual agreement. Report published in sanitized form for portfolio purposes.*
