# 🛡️ Agentic Red-Team (`agentic-redteam`)

**Target-agnostic adversarial security testing harness for AI agents taking real-world actions.**

> Designed for security engineers and AI architects evaluating agents that execute tool calls, write to databases, process payments, or handle sensitive data (OWASP LLM01, LLM02, LLM06).

---

## Key Capabilities

- **OWASP Alignment**: Evaluates agents against **LLM01 Prompt Injection**, **LLM02 Sensitive Data Leakage**, and **LLM06 Excessive Agency** (unauthorized spend/tool-calling).
- **Network-Independent Execution**: Runs assertions locally via JavaScript/Python evaluation engines without requiring remote test services.
- **Target-Agnostic HTTP Runner**: Test any OpenAI-compatible API, custom gateway, or HTTP endpoint (`/v1/chat/completions`, `/api/v1/govern`).
- **CI/CD Gating**: Command-line flag `--ci` returns non-zero status when critical security categories fail, blocking unsafe deployments in CI pipelines.

---

## Quick Start

### Installation

```bash
pip install agentic-redteam
# OR install locally
git clone https://github.com/muneeb/agentic-redteam.git
cd agentic-redteam
pip install -e .
```

### Basic Usage

```bash
# Run against a local governance service or API endpoint
agentic-redteam --target-url http://localhost:8000/api/v1/govern

# Run specific attack categories
agentic-redteam jailbreak action_level pii_leakage --target-url http://localhost:8000/api/v1/govern

# CI Enforcement Mode (fails build if critical categories regress)
agentic-redteam --ci --target-url http://localhost:8000/api/v1/govern
```

---

## Included Payload Categories

| Category | OWASP Mapping | Focus |
|---|---|---|
| `jailbreak` | LLM01 / LLM06 | Semantic jailbreaks (DAN, Developer Mode, roleplay bypass, compliance framing) |
| `prompt_injection` | LLM01 | Direct & indirect prompt injection, system prompt override, delimiter escaping |
| `action_level` | LLM06 | Excessive agency, procurement spend-cap bypass, root command execution, parameter manipulation |
| `pii_leakage` | LLM02 | Credit card numbers, SSNs, US phone numbers, DB connection strings, API keys |
| `code_safety` | LLM06 | Destructive system execution (`rm -rf`, `dd`, `DROP DATABASE`, `chmod 777`) |
| `schema_compliance` | System Integrity | Pydantic / RAIL output schema conformance under adversarial input |
| `clean_queries` | Usability | Over-block verification on legitimate business queries |

---

## Target Compatibility

`agentic-redteam` supports any JSON-over-HTTP API. It sends:
```json
{
  "query": "<payload_text>"
}
```
And parses responses formatted as OpenAI Chat Completions or custom status objects (`{"status": "blocked", ...}`).

---

## License

Apache-2.0 © 2026 Muneeb.
