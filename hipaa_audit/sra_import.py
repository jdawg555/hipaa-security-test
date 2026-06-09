"""Import browser SRA JSON exports (l0lsec/hipaa-sra, SaberGuard) into Markdown."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class SraControlRow:
    control_id: str
    category: str
    citation: str
    text: str
    response: str
    score: int | None
    notes: str


def detect_format(data: dict[str, Any]) -> str:
    if data.get("version") == 2 and "responses" in data:
        return "l0lsec"
    if "meta" in data and "responses" in data:
        return "saberguard"
    if "responses" in data:
        return "generic"
    raise ValueError("Unrecognized SRA JSON — expected responses object (l0lsec or SaberGuard export)")


def _score_label(value: Any) -> tuple[str, int | None]:
    if value is None:
        return "Unanswered", None
    if isinstance(value, str):
        lower = value.lower()
        if lower in ("yes", "2"):
            return "Yes", 2
        if lower in ("partial", "1"):
            return "Partial", 1
        if lower in ("no", "0"):
            return "No", 0
        return value, None
    if isinstance(value, (int, float)):
        iv = int(value)
        if iv >= 2:
            return "Yes", 2
        if iv == 1:
            return "Partial", 1
        if iv == 0:
            return "No", 0
    return str(value), None


def parse_rows(data: dict[str, Any], fmt: str) -> list[SraControlRow]:
    responses: dict[str, Any] = data.get("responses") or {}
    notes: dict[str, str] = data.get("notes") or {}
    rows: list[SraControlRow] = []

    if fmt == "l0lsec":
        # Optional embedded control catalog in export (future); fall back to ids only.
        for cid, raw in responses.items():
            label, score = _score_label(raw)
            rows.append(
                SraControlRow(
                    control_id=cid,
                    category="",
                    citation="",
                    text=cid,
                    response=label,
                    score=score,
                    notes=notes.get(cid, ""),
                )
            )
        return rows

    # SaberGuard / generic: responses keyed by control id; notes parallel
    for cid, raw in responses.items():
        label, score = _score_label(raw)
        rows.append(
            SraControlRow(
                control_id=cid,
                category="",
                citation="",
                text=cid.replace("-", " ").title(),
                response=label,
                score=score,
                notes=notes.get(cid, ""),
            )
        )
    return rows


def _metadata_block(data: dict[str, Any], fmt: str) -> dict[str, str]:
    if fmt == "l0lsec":
        meta = data.get("metadata") or {}
        risk = data.get("risk") or {}
        att = data.get("attestation") or {}
        return {
            "org_name": str(meta.get("orgName") or meta.get("organization") or ""),
            "assess_date": str(meta.get("assessDate") or meta.get("date") or ""),
            "assessor": str(meta.get("assessor") or ""),
            "scope": str(meta.get("scope") or meta.get("orgType") or ""),
            "score": str(meta.get("score") or ""),
            "risk_level": str(risk.get("level") or meta.get("riskLevel") or ""),
            "signatory": str(att.get("name") or att.get("executive") or ""),
            "sign_date": str(att.get("date") or ""),
        }
    meta = data.get("meta") or {}
    return {
        "org_name": str(meta.get("orgName") or ""),
        "assess_date": str(meta.get("assessDate") or ""),
        "assessor": str(meta.get("assessor") or ""),
        "scope": str(meta.get("scope") or ""),
        "score": str(meta.get("score") or ""),
        "risk_level": str(meta.get("riskLevel") or ""),
        "signatory": str(meta.get("exec") or ""),
        "sign_date": str(meta.get("signDate") or ""),
    }


def _gap_threat_rows(rows: list[SraControlRow]) -> list[str]:
    lines: list[str] = []
    n = 1
    for row in rows:
        if row.response not in ("No", "Partial"):
            continue
        threat = row.text if row.text != row.control_id else row.control_id
        lines.append(
            f"| {n} | {threat[:60]} | ePHI systems | Med | "
            f"{'High' if row.response == 'No' else 'Med'} | "
            f"{'High' if row.response == 'No' else 'Med'} | "
            f"SRA gap ({row.response}) | {row.notes or 'TBD'} | TBD |"
        )
        n += 1
    return lines


def render_imported_markdown(
    data: dict[str, Any],
    *,
    base_template: Path | None = None,
) -> str:
    fmt = detect_format(data)
    meta = _metadata_block(data, fmt)
    rows = parse_rows(data, fmt)
    answered = [r for r in rows if r.response != "Unanswered"]
    gaps = [r for r in rows if r.response in ("No", "Partial")]
    yes = sum(1 for r in rows if r.response == "Yes")
    total = len(rows) or 1
    pct = round(100 * yes / total)

    parts: list[str] = []
    if base_template and base_template.exists():
        parts.append(base_template.read_text().rstrip())
        parts.append("\n\n---\n\n")
    else:
        parts.append("# HIPAA Security Risk Assessment (imported)\n\n")

    parts.append("## Imported SRA snapshot\n\n")
    parts.append(f"_Generated by hipaa-audit import-sra · {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}_\n\n")
    parts.append(f"- **Source format:** {fmt}\n")
    parts.append(f"- **Organization:** {meta['org_name'] or '_(not in export)_'}\n")
    parts.append(f"- **Assessment date:** {meta['assess_date'] or '_(not in export)_'}\n")
    parts.append(f"- **Assessor:** {meta['assessor'] or '_(not in export)_'}\n")
    parts.append(f"- **Scope:** {meta['scope'] or '_(not in export)_'}\n")
    parts.append(f"- **Score / risk:** {meta['score'] or pct}% compliant · {meta['risk_level'] or 'see gaps'}\n")
    parts.append(f"- **Controls answered:** {len(answered)}/{len(rows)} · **Gaps:** {len(gaps)}\n\n")

    parts.append("### Section 1 — Scope (from export)\n\n")
    parts.append("| Field | Value |\n|-------|-------|\n")
    parts.append(f"| Application / org | {meta['org_name']} |\n")
    parts.append(f"| Date of assessment | {meta['assess_date']} |\n")
    parts.append(f"| Scope notes | {meta['scope']} |\n\n")

    parts.append("### Section 6 — Threats from SRA gaps\n\n")
    parts.append("| # | Threat | Asset | L | I | Risk | Control | Residual |\n")
    parts.append("|---|--------|-------|---|---|------|---------|----------|\n")
    threat_lines = _gap_threat_rows(rows)
    if threat_lines:
        parts.extend(line + "\n" for line in threat_lines)
    else:
        parts.append("| — | No Partial/No responses in import | — | — | — | — | — | — |\n")

    parts.append("\n### Appendix C — Control responses (imported)\n\n")
    parts.append("| ID | Response | Notes |\n|----|----------|-------|\n")
    for row in sorted(rows, key=lambda r: r.control_id):
        note = row.notes.replace("|", "\\|")[:120]
        parts.append(f"| {row.control_id} | {row.response} | {note} |\n")

    if meta["signatory"] or meta["sign_date"]:
        parts.append("\n### Section 8 — Sign-off (from export)\n\n")
        parts.append("| Role | Name | Date |\n|------|------|------|\n")
        parts.append(f"| Executive attestation | {meta['signatory']} | {meta['sign_date']} |\n")

    parts.append(
        "\n> Review and merge into your canonical SRA. Browser exports are a starting point — "
        "not a substitute for engineering validation or officer sign-off.\n"
    )
    return "".join(parts)


def write_import_artifacts(
    data: dict[str, Any],
    *,
    output_md: Path,
    evidence_dir: Path,
    base_template: Path | None = None,
) -> dict[str, Path]:
    fmt = detect_format(data)
    rows = parse_rows(data, fmt)
    gaps = [r for r in rows if r.response in ("No", "Partial")]
    md = render_imported_markdown(data, base_template=base_template)
    output_md.parent.mkdir(parents=True, exist_ok=True)
    output_md.write_text(md)

    evidence_dir.mkdir(parents=True, exist_ok=True)
    summary_path = evidence_dir / "sra-import-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "format": fmt,
                "controls_total": len(rows),
                "gaps": len(gaps),
                "output_markdown": str(output_md),
                "gap_controls": [r.control_id for r in gaps[:50]],
            },
            indent=2,
        )
    )
    return {"markdown": output_md, "summary": summary_path}


def load_sra_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("SRA JSON root must be an object")
    return raw
