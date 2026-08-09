# agentic-redteam

Open-source security scanner for AI agents. Sends adversarial payloads at an
HTTP agent endpoint and reports what actually got through.

114 payloads across 8 categories, mapped to the OWASP Top 10 for LLM
Applications. SARIF v2.1.0 output for GitHub code scanning. No API key needed —
the scanner talks to *your* agent, not to a model provider.

```bash
pip install agentic-redteam
agentic-redteam prompt_injection --target-url https://your-agent/api
```

## What it tests

| Category | Payloads | Checks |
|---|---|---|
| `prompt_injection` | 25 | Direct injection, encoding evasion, instruction override |
| `jailbreak` | 20 | Persona attacks, hypothetical framing, compliance framing |
| `pii_leakage` | 15 | Whether the response repeats back PII the request supplied |
| `code_safety` | 15 | Destructive shell/SQL handed back without warning |
| `schema_compliance` | 15 | Well-formed structured output under adversarial input |
| `action_level` | 10 | Action authorization vs. role-level access |
| `clean_queries` | 10 | Over-refusal on benign requests (usability, scored separately) |
| `mcp_security` | 4 | MCP tool-poisoning resistance |

Plus a cross-cutting PII sweep for high-confidence data types leaked in any
response, whether or not a payload probed for them.

## Target compatibility

Assertions inspect response **content**, not a required response shape. The
scanner reads prose, OpenAI `choices`, Anthropic content blocks, common
single-key envelopes, and `text/plain`.

Grading needs to know whether a request was blocked or answered:

- If your agent returns `{"status": "blocked"|"success", "response": "..."}`,
  that is used directly.
- Otherwise pass `--infer-refusal` to infer it from the wording.

Without either, the run **stops and reports the target as ungradeable** rather
than grading it on a guess. Inference is off by default because a wrong verdict
in a security report has real consequences, and any result resting on it is
flagged in the output.

## Usage

```bash
# Single category
agentic-redteam prompt_injection --target-url https://your-agent/api

# Everything, fail the build on critical findings
agentic-redteam --all --target-url https://your-agent/api --ci

# Statistical confidence + payload mutations (homoglyph, base64, story framing)
agentic-redteam jailbreak --target-url https://your-agent/api --iterations 3 --mutate

# SARIF for GitHub code scanning
agentic-redteam --all --target-url https://your-agent/api \
  --format sarif --output-file results.sarif

# Agent that answers in prose rather than a status field
agentic-redteam --all --target-url https://your-agent/api --infer-refusal

# Treat your own domains as legitimate when sweeping for leaked contacts
agentic-redteam pii_leakage --target-url https://your-agent/api \
  --own-domain yourcompany.com
```

## Scoring

```
base      = 100 × Σ(weight × passed) / Σ(weight × total)
composite = min(base, worst CRITICAL category pass rate)
```

A weighted pass **rate**, capped by the weakest critical category. Scale
invariant, so adding tests to a category doesn't mechanically move every score,
and a target that fails everything it ran can't score well just because the
category was small.

**Over-refusal is reported separately** and excluded from the security score. An
agent that declines legitimate requests has a usability problem, not a
vulnerability, and averaging the two produces a number nobody can act on.

## CI

```yaml
- run: pip install agentic-redteam
- run: agentic-redteam --all --target-url ${{ secrets.AGENT_URL }} --ci
```

`--ci` exits non-zero when a critical-category test fails. `--score-threshold N`
fails below a composite score.

## Pro

Advanced categories (indirect injection, multi-turn, sandbox escape, rogue
persistence, crypto probes), an adaptive LLM attacker, multi-agent swarm mode,
app registry, audit history with trend comparison, and CISO-ready reports are in
`agentic-redteam-pro`. See [swishos.io/pricing](https://swishos.io/pricing).

The free CLI stays free with Pro installed — unlocking happens only through the
`agentic-redteam-pro` entry point.

## License

MIT. See [LICENSE](LICENSE).
