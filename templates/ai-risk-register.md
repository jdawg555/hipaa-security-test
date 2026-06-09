# AI / ML Risk Register (clinical & operational systems)

Use when LLMs, classifiers, or automated decision support touch PHI or clinical workflows.
Map rows into SRA section 6.

| ID | Risk | Likelihood | Impact | PHI? | Existing control | Residual | Owner |
|----|------|------------|--------|------|------------------|----------|-------|
| AI-01 | **Prompt injection** via user/clinical content in LLM context | Med | High | Y | Input sanitization, tool allowlists, no PHI in prompts where avoidable | Med | |
| AI-02 | **Training data leakage** — model memorizes PHI | Low | High | Y | No fine-tuning on prod PHI; synthetic/redacted training only | Low | |
| AI-03 | **Model drift** degrades safety over time | Med | Med | Y | Eval harness, regression suite, version pinning | Med | |
| AI-04 | **Hallucinated clinical content** sent to patients | Med | High | Y | Human-in-loop for all patient-facing automated content | Med | |
| AI-05 | **Subprocessor model API** (OpenAI, Anthropic, etc.) | Med | High | Y | BAA/DPA, zero-retention flags, regional routing | Med | |
| AI-06 | **Clinician override bypass** — staff trusts bad output | Med | High | Y | UI shows confidence + source; audit log of accepts/rejects | Med | |
| AI-07 | **Agent tool over-permission** — LLM calls dangerous APIs | Low | High | Y | Least-privilege tools, confirmation for writes | Low | |
| AI-08 | **Log retention of prompts** contains PHI | Med | Med | Y | PHI scrubbing in logs, short retention | Low | |

## Model inventory

| Model / service | Version | PHI in prompts? | BAA/DPA | Eval last run |
|-----------------|---------|-----------------|---------|---------------|
| | | | | |
