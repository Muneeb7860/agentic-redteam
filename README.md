# 🛡️ `agentic-redteam`: Frontier-Grade AI Agent Security Harness & Benchmark

[![PyPI version](https://img.shields.io/badge/pypi-v0.5.0-blue.svg)](pyproject.toml)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`agentic-redteam` is an enterprise open-source security scanner, benchmark runner, and Generative Adversarial Red Teaming (GART) harness designed to evaluate AI agents and LLM API endpoints against OWASP LLM Top 10 vulnerabilities.

---

## ⚡ Key Features

- 🎯 **10 Comprehensive Threat Categories**: Action-level overreach, centroid novel metaphors, code safety, indirect injection, jailbreak framing, multi-turn variable AST splitting, PII exfiltration, prompt injection, schema compliance, and cryptographic identity probes.
- 🤖 **GART Mode (Generative Agentic Red Teaming)**: Target-guided LLM attacker loop using OpenAI, Anthropic, or Gemini to dynamically generate adversarial jailbreak prompt mutations.
- 🔑 **Cryptographic Telemetry Verifier**: Validates `X-SwishOS-Audit-Proof` HMAC headers to catch fake/hallucinated LLM JSON error responses.
- ⏱️ **Subnet Fingerprint Tarpit Stress-Tester**: Measures target server exponential tarpits by simulating `/24` IPv4 proxy cluster rotations.
- 📊 **Dual Benchmark Reports**: Exports human-readable `BENCHMARK_REPORT.md` and machine-readable `benchmark_results.json` for CI/CD pipeline security gates.

---

## 🚀 Installation & Usage

### 1. Installation via Pip
```bash
pip install pyyaml cryptography
# Or editable mode
pip install -e .
```

### 2. Command Line Interface (CLI)
```bash
# Basic Audit Sweep
agentic-redteam --target http://localhost:3000/api/support

# Deep Audit Sweep (N=10 Iterations + Local Mutations)
agentic-redteam --target http://localhost:3000/api/support --deep --mutate

# GART Generative LLM Attacker Sweep (OpenAI / Anthropic / Gemini)
export OPENAI_API_KEY="your-api-key"
agentic-redteam --target http://localhost:3000/api/support --use-llm-attacker --attacker-provider openai
```

### 3. Programmatic Python SDK Usage
```python
from agentic_redteam import RedTeamHarness, run_crypto_probes, verify_audit_proof_header

# Run Cryptographic Identity Probes
crypto_results = run_crypto_probes("http://localhost:3000/api/support")
print("Crypto Probes:", crypto_results)

# Run Automated Benchmark Suite
from agentic_redteam.benchmark_runner import run_automated_benchmark
summary = run_automated_benchmark("http://localhost:3000/api/support")
print(f"Overall Pass Rate: {summary['overall_pass_rate']}%")
```

---

## 📜 License
MIT License. Developed by SwishOS Security Research Team.
