from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import hashlib
from typing import Any

from services.inventory import build_inventory


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _display(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text.replace("_", " ").replace("-", " ").title()


def _slug(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "_" for ch in str(value or "")).strip("_") or "item"


def _stable_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha1("|".join(str(part or "") for part in parts).encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def _severity_label(value: object) -> str:
    try:
        sev = int(value or 4)
    except Exception:
        sev = 4
    return {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}.get(sev, "Low")


def _severity_rank(label: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(str(label or "Low"), 3)


def _stride_for_finding(finding: dict[str, Any]) -> str:
    provider = str(finding.get("provider_or_lib", "") or "").lower()
    description = str(finding.get("description", "") or "").lower()
    if any(token in provider for token in ("secret", "key", "credential")):
        return "Information disclosure"
    if any(token in provider for token in ("prompt", "rag", "http_response_to_llm", "file_content_to_llm", "db_results_to_llm")):
        return "Tampering"
    if any(token in provider for token in ("unsafe_code_exec", "agent", "tool", "sql_injection_risk")):
        return "Elevation of privilege"
    if any(token in provider for token in ("model_serv", "vllm", "ollama", "llama_cpp")):
        return "Spoofing"
    if "denial" in description or "dos" in description:
        return "Denial of service"
    return "Information disclosure"


def _threat_title(finding: dict[str, Any]) -> str:
    provider_slug = str(finding.get("provider_or_lib", "") or "").lower()
    special_titles = {
        "secret_ai_correlation": "Secret leakage into AI workflows",
        "prompt_injection_risk": "Prompt injection from untrusted content",
        "rag_pattern": "RAG poisoning or malicious retrieval influence",
        "file_content_to_llm": "Sensitive data exfiltration to model endpoints",
        "dataframe_to_llm": "Sensitive data exfiltration to model endpoints",
        "db_results_to_llm": "Sensitive data exfiltration to model endpoints",
        "http_response_to_llm": "Prompt injection from untrusted content",
        "unsafe_code_exec": "Unsafe tool execution from agent decisions",
        "remote_model_load": "Model or artifact supply-chain compromise",
        "unsafe_torch_load": "Model or artifact supply-chain compromise",
        "unsafe_pickle_model": "Model or artifact supply-chain compromise",
    }
    if provider_slug in special_titles:
        return special_titles[provider_slug]
    provider = _display(str(finding.get("provider_or_lib", "") or "AI risk"))
    file_name = str(finding.get("file", "") or "")
    if file_name:
        return f"{provider} in {file_name}"
    return provider


def _mitigations_for_finding(finding: dict[str, Any]) -> list[str]:
    provider = str(finding.get("provider_or_lib", "") or "").lower()
    mitigations = []
    if any(token in provider for token in ("secret", "key", "credential")):
        mitigations.extend([
            "Move credentials to a managed secret store and rotate any exposed values.",
            "Prevent secret-bearing values from entering prompts, logs, and model requests.",
        ])
    if any(token in provider for token in ("prompt", "rag", "file_content_to_llm", "db_results_to_llm", "http_response_to_llm")):
        mitigations.extend([
            "Treat user, document, and retrieved content as untrusted input before prompt assembly.",
            "Add allowlists, validation, and content controls before model invocation.",
        ])
    if any(token in provider for token in ("agent", "tool", "unsafe_code_exec")):
        mitigations.extend([
            "Require explicit approval and argument validation for model-triggered actions.",
            "Restrict execution to allowlisted tools with audited inputs and outputs.",
        ])
    if any(token in provider for token in ("vllm", "ollama", "model_serv", "remote_model_load", "unsafe_pickle_model", "unsafe_torch_load")):
        mitigations.extend([
            "Pin trusted model/artifact sources and verify integrity before loading.",
            "Isolate model-serving endpoints behind authentication, TLS, and network controls.",
        ])
    if not mitigations:
        mitigations.extend([
            "Review the affected code path and document whether the AI behavior is intentional and controlled.",
            "Add boundary checks, logging, and policy controls around this AI interaction.",
        ])
    seen = set()
    unique = []
    for item in mitigations:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique[:3]


def build_threat_model(findings: list[dict[str, Any]], *, meta: dict[str, Any] | None = None, replay_instructions: str = "") -> dict[str, Any]:
    meta = dict(meta or {})
    inventory = dict(meta.get("inventory") or build_inventory(findings))
    repo_label = str(meta.get("repo", "") or "")
    project_key = str(meta.get("project_key", "") or "")
    repo_profiles = list(inventory.get("repo_profiles") or [])
    provider_names = sorted({_display(str(f.get("provider_or_lib", "") or "")) for f in findings if str(f.get("provider_or_lib", "") or "").strip()})
    model_names = sorted({str(model).strip() for model in inventory.get("models", []) if str(model).strip()})
    contexts = Counter(str(f.get("context", "production") or "production").lower() for f in findings)
    findings_by_provider = Counter(str(f.get("provider_or_lib", "") or "").strip() for f in findings if str(f.get("provider_or_lib", "") or "").strip())

    observed_signals = []
    if inventory.get("repos_using_ai_count", 0):
        observed_signals.append(f"{inventory.get('repos_using_ai_count', 0)} repo(s) with AI usage")
    if inventory.get("provider_count", 0):
        observed_signals.append(f"{inventory.get('provider_count', 0)} provider(s) detected")
    if inventory.get("model_count", 0):
        observed_signals.append(f"{inventory.get('model_count', 0)} model reference(s) detected")
    if inventory.get("prompt_handling_repos", 0):
        observed_signals.append("Prompt and model I/O handling detected")
    if inventory.get("embeddings_vector_db_repos", 0):
        observed_signals.append("Embeddings or vector retrieval detected")
    if inventory.get("model_serving_repos", 0):
        observed_signals.append("Model-serving behavior detected")
    if inventory.get("agent_tool_use_repos", 0):
        observed_signals.append("Agent or tool-use patterns detected")
    if findings_by_provider.get("secret_ai_correlation", 0):
        observed_signals.append("Secret-to-AI correlation findings present")

    actors = [
        {"id": _stable_id("actor", "user"), "name": "User / Browser", "kind": "external_actor"},
        {"id": _stable_id("actor", "developer"), "name": "Developer / Operator", "kind": "internal_actor"},
    ]
    if inventory.get("prompt_handling_repos", 0):
        actors.append({"id": _stable_id("actor", "content"), "name": "Untrusted Content Source", "kind": "external_actor"})
    if provider_names:
        actors.append({"id": _stable_id("actor", "provider"), "name": "External / Local AI Provider", "kind": "service_actor"})

    processes = [
        {"id": _stable_id("proc", "app"), "name": "Application Runtime", "kind": "application"},
        {"id": _stable_id("proc", "analysis"), "name": "AI Integration Layer", "kind": "integration"},
    ]
    if inventory.get("agent_tool_use_repos", 0):
        processes.append({"id": _stable_id("proc", "agent"), "name": "Agent / Tool Orchestrator", "kind": "agent"})
    if inventory.get("model_serving_repos", 0):
        processes.append({"id": _stable_id("proc", "serving"), "name": "Model Serving Endpoint", "kind": "serving"})
    if inventory.get("embeddings_vector_db_repos", 0):
        processes.append({"id": _stable_id("proc", "rag"), "name": "Retrieval Pipeline", "kind": "retrieval"})

    stores = [
        {"id": _stable_id("store", "config"), "name": "Configuration / Secrets", "kind": "config"},
        {"id": _stable_id("store", "logs"), "name": "Logs / Outputs", "kind": "logging"},
    ]
    if inventory.get("embeddings_vector_db_repos", 0):
        stores.append({"id": _stable_id("store", "vector"), "name": "Vector Store / Knowledge Base", "kind": "vector_store"})
    if any("db" in str(f.get("provider_or_lib", "") or "").lower() for f in findings):
        stores.append({"id": _stable_id("store", "db"), "name": "Database / Internal Records", "kind": "database"})
    if any(token in str(f.get("provider_or_lib", "") or "").lower() for f in findings for token in ("unsafe_torch_load", "unsafe_pickle_model", "remote_model_load")):
        stores.append({"id": _stable_id("store", "model"), "name": "Model Artifacts", "kind": "model_artifacts"})

    boundaries = [
        {"id": _stable_id("boundary", "app"), "name": "Application Trust Boundary", "kind": "internal"},
    ]
    if provider_names:
        boundaries.append({"id": _stable_id("boundary", "provider"), "name": "AI Provider Boundary", "kind": "external_service"})
    if inventory.get("prompt_handling_repos", 0):
        boundaries.append({"id": _stable_id("boundary", "input"), "name": "Untrusted Input Boundary", "kind": "content"})
    if inventory.get("embeddings_vector_db_repos", 0):
        boundaries.append({"id": _stable_id("boundary", "retrieval"), "name": "Retrieval Boundary", "kind": "retrieval"})

    flow_specs = [
        ("User Request", actors[0]["id"], processes[0]["id"], True),
        ("Application Data to AI", processes[0]["id"], processes[1]["id"], bool(provider_names)),
    ]
    if provider_names:
        flow_specs.append(("Prompt / Model Request", processes[1]["id"], actors[-1]["id"], True))
    if inventory.get("agent_tool_use_repos", 0):
        flow_specs.append(("Model Decision to Tool Action", processes[1]["id"], _stable_id("proc", "agent"), False))
    if inventory.get("embeddings_vector_db_repos", 0):
        flow_specs.append(("Retrieved Context", _stable_id("store", "vector"), _stable_id("proc", "rag"), False))
        flow_specs.append(("Context into Prompt", _stable_id("proc", "rag"), processes[1]["id"], False))
    flows = [
        {
            "id": _stable_id("flow", name, src, dst),
            "name": name,
            "source": src,
            "target": dst,
            "crosses_boundary": crosses_boundary,
        }
        for name, src, dst, crosses_boundary in flow_specs
    ]

    threats = []

    def add_summary_threat(title: str, severity: str, stride: str, description: str, evidence: str, mitigations: list[str]) -> None:
        threats.append({
            "id": _stable_id("threat", "summary", title),
            "title": title,
            "severity": severity,
            "stride": stride,
            "target": "AI Integration Layer",
            "source": "Architecture Signal",
            "description": description,
            "evidence": {"file": evidence, "line": "", "provider_or_lib": "", "why_flagged": ""},
            "mitigations": mitigations[:3],
        })

    if findings_by_provider.get("secret_ai_correlation", 0):
        add_summary_threat(
            "Secret leakage into AI workflows",
            "Critical",
            "Information disclosure",
            "Credentials or secret-like material appear near active AI paths, increasing the risk of exfiltration to model providers, logs, or derived artifacts.",
            f"{findings_by_provider.get('secret_ai_correlation', 0)} correlated secret-to-AI finding(s)",
            [
                "Move credentials into managed secret storage and rotate exposed values.",
                "Prevent secret-bearing material from entering prompts, logs, and model requests.",
            ],
        )
    if inventory.get("prompt_handling_repos", 0):
        add_summary_threat(
            "Prompt injection from untrusted content",
            "High",
            "Tampering",
            "Prompt handling was detected, so user input, documents, or remote content may be able to steer model behavior or downstream actions.",
            f"Prompt-handling signals in {inventory.get('prompt_handling_repos', 0)} repo(s)",
            [
                "Isolate system instructions from user and retrieved content.",
                "Apply content controls before prompt assembly and tool invocation.",
            ],
        )
    if inventory.get("embeddings_vector_db_repos", 0):
        add_summary_threat(
            "RAG poisoning or malicious retrieval influence",
            "High",
            "Tampering",
            "Retrieved context can become a control channel if ingestion, ranking, or provenance validation is weak.",
            "Embeddings or vector retrieval were detected",
            [
                "Validate ingestion sources and attach provenance to retrieved chunks.",
                "Constrain what retrieved text can influence in downstream prompts or tools.",
            ],
        )
    if inventory.get("agent_tool_use_repos", 0):
        add_summary_threat(
            "Unsafe tool execution from agent decisions",
            "Critical",
            "Elevation of privilege",
            "Agent or tool-use patterns create a path from model output to action, amplifying prompt injection or bad reasoning into real changes.",
            f"Agent/tool-use signals in {inventory.get('agent_tool_use_repos', 0)} repo(s)",
            [
                "Restrict execution to allowlisted tools with validated arguments.",
                "Require approval boundaries and auditable action logs for model-triggered operations.",
            ],
        )
    if any(provider in findings_by_provider for provider in ("file_content_to_llm", "dataframe_to_llm", "db_results_to_llm", "http_response_to_llm")):
        add_summary_threat(
            "Sensitive data exfiltration to model endpoints",
            "High",
            "Information disclosure",
            "Repository patterns indicate that application data may be sent directly to model endpoints, increasing confidentiality and policy risk.",
            "Data-to-LLM patterns were flagged in the scan",
            [
                "Classify and minimize outbound data before prompt assembly.",
                "Enforce policy checks before sending internal records to models.",
            ],
        )
    if inventory.get("model_serving_repos", 0) or any(provider in findings_by_provider for provider in ("remote_model_load", "unsafe_torch_load", "unsafe_pickle_model")):
        add_summary_threat(
            "Model or artifact supply-chain compromise",
            "High",
            "Spoofing",
            "Unsafe model loading or model-serving paths can turn model artifacts into integrity, authenticity, or code-execution risks.",
            "Model-serving or unsafe model-load signals were detected",
            [
                "Pin trusted model sources and verify artifact integrity.",
                "Protect model-serving endpoints with authentication, TLS, and network controls.",
            ],
        )

    for finding in findings:
        file_name = str(finding.get("file", "") or "")
        if not file_name:
            continue
        threat = {
            "id": _stable_id("threat", finding.get("_hash", ""), file_name, finding.get("line", "")),
            "title": _threat_title(finding),
            "severity": _severity_label(finding.get("severity", 4)),
            "stride": _stride_for_finding(finding),
            "target": "AI Integration Layer",
            "source": "User / Browser" if str(finding.get("context", "production") or "production").lower() in {"production", "test"} else "Untrusted Content Source",
            "description": str(finding.get("description", "") or f"Finding detected in {file_name}."),
            "evidence": {
                "file": file_name,
                "line": finding.get("line", ""),
                "provider_or_lib": str(finding.get("provider_or_lib", "") or ""),
                "why_flagged": str(finding.get("why_flagged", "") or ""),
            },
            "mitigations": _mitigations_for_finding(finding),
        }
        threats.append(threat)
    deduped = []
    seen_titles = set()
    for item in threats:
        title_key = str(item.get("title", "")).strip().lower()
        if title_key and title_key not in seen_titles:
            seen_titles.add(title_key)
            deduped.append(item)
    deduped.sort(key=lambda item: (_severity_rank(item["severity"]), item["title"]))
    threats = deduped[:15]

    gaps = []
    threat_titles = " ".join(item["title"].lower() + " " + item["description"].lower() for item in threats)
    if inventory.get("prompt_handling_repos", 0) and "prompt" not in threat_titles:
        gaps.append("Prompt handling is present, but explicit prompt-injection threat coverage is still thin.")
    if inventory.get("embeddings_vector_db_repos", 0) and "retriev" not in threat_titles and "rag" not in threat_titles:
        gaps.append("RAG/vector usage was detected, but poisoning and retrieval-integrity threats need deeper coverage.")
    if inventory.get("agent_tool_use_repos", 0) and "tool" not in threat_titles and "agent" not in threat_titles:
        gaps.append("Agent/tool execution was detected, but action-governance threats should be reviewed explicitly.")
    if inventory.get("model_serving_repos", 0) and "serv" not in threat_titles and "endpoint" not in threat_titles:
        gaps.append("Model-serving behavior exists, but caller authentication and abuse scenarios need validation.")
    if findings_by_provider.get("secret_ai_correlation", 0) == 0 and any("key" in provider.lower() or "secret" in provider.lower() for provider in findings_by_provider):
        gaps.append("Credential exposure signals exist; verify whether any secrets can reach prompt, model, or logging paths.")
    if not gaps:
        gaps.append("No major structural threat-model gaps were inferred from the current scan, but trust-boundary validation still requires human review.")

    attack_trees = []
    for threat in threats[:3]:
        attack_trees.append({
            "title": threat["title"],
            "root": f"Exploit {threat['title']}",
            "paths": [
                f"Identify reachable path in {threat['evidence'].get('file') or 'repository'}",
                f"Abuse {threat['source']} input or boundary crossing to target {threat['target']}",
                f"Impact confidentiality/integrity through {threat['stride'].lower()} scenario",
            ],
        })

    return {
        "version": 1,
        "generated_at_utc": _utc_now(),
        "replay_instructions": str(replay_instructions or "").strip(),
        "summary": {
            "project_key": project_key,
            "repo": repo_label,
            "provider_labels": provider_names,
            "models": model_names,
            "contexts": dict(contexts),
            "finding_count": len(findings),
        },
        "stages": {
            "architecture": {
                "observed_signals": observed_signals[:8],
                "actors": actors,
                "processes": processes,
                "stores": stores,
                "flows": flows,
                "boundaries": boundaries,
                "repo_profiles": repo_profiles,
            },
            "assets": [
                "Application secrets and provider credentials",
                "User prompts, retrieved context, and model outputs",
                "Internal source code, operational data, and configuration",
            ] + (["Embedding stores and retrieved knowledge bases"] if inventory.get("embeddings_vector_db_repos", 0) else []),
            "threats": threats,
            "gaps": gaps[:5],
            "attack_trees": attack_trees,
        },
    }


def build_threat_dragon_model(findings: list[dict[str, Any]], *, meta: dict[str, Any] | None = None, replay_instructions: str = "") -> dict[str, Any]:
    model = build_threat_model(findings, meta=meta, replay_instructions=replay_instructions)
    architecture = dict(model["stages"]["architecture"])
    threats = list(model["stages"]["threats"])

    def actor_cell(item: dict[str, Any], x: int, y: int) -> dict[str, Any]:
        return {
            "type": "tm.Actor",
            "id": item["id"],
            "position": {"x": x, "y": y},
            "size": {"width": 160, "height": 80},
            "threats": [],
            "outOfScope": False,
            "hasOpenThreats": False,
            "attrs": {"text": {"text": item["name"]}},
        }

    def process_cell(item: dict[str, Any], x: int, y: int, item_threats: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": "tm.Process",
            "id": item["id"],
            "position": {"x": x, "y": y},
            "size": {"width": 110, "height": 110},
            "threats": item_threats,
            "outOfScope": False,
            "hasOpenThreats": bool(item_threats),
            "attrs": {"text": {"text": item["name"].replace(" ", "\n", 1)}},
        }

    def store_cell(item: dict[str, Any], x: int, y: int, item_threats: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": "tm.Store",
            "id": item["id"],
            "position": {"x": x, "y": y},
            "size": {"width": 170, "height": 80},
            "threats": item_threats,
            "outOfScope": False,
            "hasOpenThreats": bool(item_threats),
            "attrs": {"text": {"text": item["name"]}},
        }

    def flow_cell(item: dict[str, Any], item_threats: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "type": "tm.Flow",
            "id": item["id"],
            "source": {"id": item["source"]},
            "target": {"id": item["target"]},
            "size": {"width": 10, "height": 10},
            "smooth": True,
            "labels": [{"position": 0.5, "attrs": {"text": {"text": item["name"], "font-size": "small"}}}],
            "threats": item_threats,
            "hasOpenThreats": bool(item_threats),
            "outOfScope": False,
            "isPublicNetwork": bool(item.get("crosses_boundary")),
            "attrs": {},
        }

    threat_by_target: dict[str, list[dict[str, Any]]] = {}
    for threat in threats:
        target = str(threat.get("target", "") or "")
        td_threat = {
            "status": "Open",
            "severity": str(threat.get("severity", "Medium")),
            "title": str(threat.get("title", "")),
            "type": str(threat.get("stride", "Information disclosure")),
            "description": str(threat.get("description", "")),
            "mitigation": "\n".join(list(threat.get("mitigations", []))[:3]),
        }
        threat_by_target.setdefault(target, []).append(td_threat)

    cells: list[dict[str, Any]] = []
    x_positions = {"actor": 40, "process": 310, "store": 590}
    for idx, item in enumerate(architecture["actors"]):
        cells.append(actor_cell(item, x_positions["actor"], 40 + idx * 130))
    for idx, item in enumerate(architecture["processes"]):
        cells.append(process_cell(item, x_positions["process"], 30 + idx * 150, threat_by_target.get(item["name"], [])))
    for idx, item in enumerate(architecture["stores"]):
        cells.append(store_cell(item, x_positions["store"], 40 + idx * 120, threat_by_target.get(item["name"], [])))
    for flow in architecture["flows"]:
        cells.append(flow_cell(flow, threat_by_target.get(flow["name"], [])))

    repo_label = str((meta or {}).get("repo", "") or "Repository")
    return {
        "summary": {
            "title": f"PhantomLM Threat Model - {repo_label}",
            "owner": str((meta or {}).get("owner", "") or "PhantomLM"),
            "description": "Threat model generated from scan evidence, repository signals, and staged analysis.",
            "id": 0,
        },
        "detail": {
            "contributors": [{"name": "PhantomLM"}],
            "reviewer": str((meta or {}).get("operator", "") or "Operator"),
            "diagrams": [
                {
                    "title": "Repository Threat Model",
                    "diagramType": "STRIDE",
                    "id": 0,
                    "size": {"width": 980, "height": 720},
                    "diagramJson": {"cells": cells},
                }
            ],
            "metadata": {
                "generated_at_utc": model["generated_at_utc"],
                "replay_instructions": model["replay_instructions"],
                "gaps": list(model["stages"]["gaps"]),
                "attack_trees": list(model["stages"]["attack_trees"]),
            },
        },
    }
