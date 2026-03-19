# PII Leak Hunter

**PII Leak Hunter** is an open-source tool for detecting **PII leaks, masking failures, and sensitive data exposure in logs**.

It helps security, AppSec, SecOps, DevSecOps and platform teams identify what should never have reached logs in the first place.


## 🔥 Features

- Detect **PII in logs** (SSN, tax IDs, IBAN, cards, etc.)
- Detect **masking failures** (partial or broken redaction)
- Detect **identity bundles** (KYC-level exposure)
- Detect **secrets + PII combinations**
- **PII detection powered by [Microsoft Presidio](https://github.com/microsoft/presidio) + custom NLP recognizers**
- **Presidio-powered detection + custom recognizers**
- **Safe previews by default** (no raw sensitive data exposed)
- **CLI for automation, CI/CD, and scripting**
- **Streamlit UI for triage, demos, and screenshots**
- Output formats:
  - JSON
  - CSV
  - SARIF
  - Markdown summary
- Built-in **demo/fixture datasets** for safe testing and screenshots


## 🧱 Built with

- [Microsoft Presidio](https://github.com/microsoft/presidio) – PII detection and analysis  
- Python 3.10+  


## 🧩 Supported providers

### Current
- **Coralogix** (v1)

### Coming soon
- Datadog  
- Dynatrace  
- Splunk  
- New Relic  


## 🎯 Use cases

- Sensitive data hunting in logs  
- Validating secure logging and masking controls  
- Supporting **Shift-Left DLP (SLDLP)** initiatives  
- Detecting privacy and compliance issues  
- Investigating incidents involving data exposure  
- Post-deployment validation (detect leaks after release)


## 🧠 Positioning

PII Leak Hunter is:

- **SLDLP-aligned** (Shift-Left Data Loss Prevention)
- **DSPM-adjacent** (logs are a real data surface)
- **Compliance-supportive** (PCI DSS, GDPR, SOC 2, HIPAA, ISO 27001)
- **Provider-agnostic** (Coralogix-first, multi-provider roadmap)


## ⚡ Quick start

### 1. Install

```bash
git clone https://github.com/your-org/pii-leak-hunter.git
cd pii-leak-hunter

python -m venv .venv
source .venv/bin/activate

pip install -e .
```


### 2. Configure

Set your Coralogix credentials:

```bash
export CORALOGIX_API_KEY=your_api_key
export CORALOGIX_REGION=your_region
```


### 3. Run scan (Coralogix)

```bash
pii-leak-hunter scan   --query 'source:"mailer-service"'   --from '-24h'   --out-json findings.json   --out-csv findings.csv   --fail-on critical
```


### 4. Run UI (Streamlit)

```bash
streamlit run pii_leak_hunter/app.py
```


### 5. Scan local logs

```bash
pii-leak-hunter scan-file logs.ndjson
```


## 📊 Example findings

- Unmasked SSN in production logs → **critical**
- Masking failure (raw + masked present) → **critical**
- IBAN with beneficiary context → **high**
- Identity bundle (name + DOB + SSN) → **critical**
- Secret + PII in same payload → **critical**


## 🔐 Safety

- No raw sensitive data shown by default  
- Values are masked in output  
- Hash-based correlation only  
- Read-only scanning (no mutations to log providers)  

To show raw values (not recommended):

```bash
--unsafe-show-values
```


## 🧱 Detection approach

PII Leak Hunter combines:

- Pattern matching (regex)
- Context-aware detection
- Field-based heuristics
- Multi-entity correlation
- Custom fintech-aware recognizers

This avoids the limitations of regex-only tools.


## 🧪 Demo & screenshots

The repository includes **synthetic datasets** for:

- safe demos
- UI screenshots
- CI testing

No real sensitive data is included.


## 🛣 Roadmap

- [x] Coralogix provider  
- [x] CLI + Streamlit UI  
- [ ] Datadog provider  
- [ ] Dynatrace provider  
- [ ] Splunk provider  
- [ ] New Relic provider  
- [ ] CI/CD integration templates  
- [ ] Advanced detection tuning  


## 🤝 Contributing

Contributions are welcome.

Focus areas:
- new recognizers
- provider adapters
- performance improvements
- false-positive reduction
- UI enhancements

Please ensure:
- no real PII is included in tests
- all new logic includes tests
- changes remain simple (KISS)


## 📄 License

MIT License

---

## 🧠 Final note

> **PII Leak Hunter helps teams detect sensitive data leaks in logs and validate secure logging controls before they become incidents.**
