from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any


_PROMPT_PROVIDER_KEYS = {
    "prompt_injection_risk",
    "file_content_to_llm",
    "dataframe_to_llm",
    "env_vars_to_llm",
    "db_results_to_llm",
    "http_response_to_llm",
}

_MODEL_SERVING_PROVIDER_KEYS = {
    "vllm",
    "ollama",
    "k8s_model_serving",
}

_AGENT_TOOL_PROVIDER_KEYS = {
    "langchain",
    "llama_index",
    "autogen",
    "crewai",
    "semantic_kernel",
    "langgraph",
    "openai_assistants",
    "llm_tool_no_authz",
    "sql_in_tool_description",
    "nocode_ai_platform",
}

_MODEL_RE = re.compile(
    r"\b("
    r"gpt-[a-z0-9.\-]+|"
    r"claude-[a-z0-9.\-]+|"
    r"gemini-[a-z0-9.\-]+|"
    r"llama[0-9.\-:a-z]*|"
    r"mistral[0-9.\-:a-z]*|"
    r"qwen[0-9.\-:a-z]*|"
    r"deepseek[0-9.\-:a-z]*|"
    r"mixtral[0-9.\-:a-z]*|"
    r"phi-[0-9.\-:a-z]+|"
    r"text-embedding-[a-z0-9.\-]+|"
    r"embed-gecko[a-z0-9.\-]*"
    r")\b",
    re.IGNORECASE,
)


def _normalise_label(value: str) -> str:
    text = str(value or "").strip().replace("_", " ")
    return " ".join(part.capitalize() if part.islower() else part for part in text.split())


def _find_models(finding: dict) -> set[str]:
    haystacks = [
        str(finding.get("match", "") or ""),
        str(finding.get("snippet", "") or ""),
        str(finding.get("capability", "") or ""),
        str(finding.get("description", "") or ""),
    ]
    models = set()
    for text in haystacks:
        for match in _MODEL_RE.findall(text):
            models.add(match)
    return models


def _is_prompt_handling(finding: dict) -> bool:
    provider = str(finding.get("provider_or_lib", "") or "")
    if provider in _PROMPT_PROVIDER_KEYS:
        return True
    hay = " ".join(
        str(finding.get(key, "") or "")
        for key in ("capability", "description", "match", "snippet")
    ).lower()
    return any(token in hay for token in ("prompt", "system message", "messages", "chat prompt", "prompttemplate"))


def _is_model_serving(finding: dict) -> bool:
    provider = str(finding.get("provider_or_lib", "") or "")
    capability = str(finding.get("capability", "") or "").lower()
    category = str(finding.get("ai_category", finding.get("category", "")) or "").lower()
    return (
        provider in _MODEL_SERVING_PROVIDER_KEYS
        or "serving" in capability
        or ("local llm runtime" in category and "server" in capability)
    )


def _is_agent_tool_use(finding: dict) -> bool:
    provider = str(finding.get("provider_or_lib", "") or "")
    capability = str(finding.get("capability", "") or "").lower()
    return (
        provider in _AGENT_TOOL_PROVIDER_KEYS
        or "tool" in capability
        or "agent" in capability
        or "orchestration" in capability
    )


def build_inventory(findings: list[dict[str, Any]], repo_slugs: list[str] | None = None) -> dict[str, Any]:
    repo_profiles: dict[str, dict[str, Any]] = {}
    provider_counts: Counter[str] = Counter()
    model_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()

    for finding in findings:
        repo = str(finding.get("repo", "") or "")
        if not repo:
            continue
        profile = repo_profiles.setdefault(repo, {
            "repo": repo,
            "finding_count": 0,
            "providers": set(),
            "models": set(),
            "categories": set(),
            "embeddings_vector_db": False,
            "prompt_handling": False,
            "model_serving": False,
            "agent_tool_use": False,
        })
        provider = str(finding.get("provider_or_lib", "") or "")
        category = str(finding.get("ai_category", finding.get("category", "")) or "")
        profile["finding_count"] += 1
        if provider:
            profile["providers"].add(provider)
            provider_counts[provider] += 1
        if category:
            profile["categories"].add(category)
            category_counts[category] += 1
        for model in _find_models(finding):
            profile["models"].add(model)
            model_counts[model] += 1
        if category in {"Embeddings", "RAG/Vector DB"}:
            profile["embeddings_vector_db"] = True
        if _is_prompt_handling(finding):
            profile["prompt_handling"] = True
        if _is_model_serving(finding):
            profile["model_serving"] = True
        if _is_agent_tool_use(finding):
            profile["agent_tool_use"] = True

    all_repos = set(repo_profiles.keys())
    if repo_slugs:
        all_repos.update(str(slug) for slug in repo_slugs if slug)

    serialised_profiles = []
    for repo in sorted(all_repos):
        base = repo_profiles.get(repo) or {
            "repo": repo,
            "finding_count": 0,
            "providers": set(),
            "models": set(),
            "categories": set(),
            "embeddings_vector_db": False,
            "prompt_handling": False,
            "model_serving": False,
            "agent_tool_use": False,
        }
        serialised_profiles.append({
            "repo": repo,
            "finding_count": base["finding_count"],
            "providers": sorted(base["providers"]),
            "provider_labels": [_normalise_label(v) for v in sorted(base["providers"])],
            "models": sorted(base["models"]),
            "categories": sorted(base["categories"]),
            "embeddings_vector_db": bool(base["embeddings_vector_db"]),
            "prompt_handling": bool(base["prompt_handling"]),
            "model_serving": bool(base["model_serving"]),
            "agent_tool_use": bool(base["agent_tool_use"]),
        })

    return {
        "repos_using_ai_count": sum(1 for profile in serialised_profiles if profile["finding_count"] > 0),
        "repos_total": len(serialised_profiles),
        "provider_count": len(provider_counts),
        "model_count": len(model_counts),
        "providers": sorted(provider_counts),
        "provider_labels": [_normalise_label(v) for v in sorted(provider_counts)],
        "models": sorted(model_counts),
        "category_counts": dict(category_counts),
        "providers_by_count": [
            {"provider": key, "label": _normalise_label(key), "count": count}
            for key, count in provider_counts.most_common()
        ],
        "models_by_count": [
            {"model": key, "count": count}
            for key, count in model_counts.most_common()
        ],
        "embeddings_vector_db_repos": sum(1 for profile in serialised_profiles if profile["embeddings_vector_db"]),
        "prompt_handling_repos": sum(1 for profile in serialised_profiles if profile["prompt_handling"]),
        "model_serving_repos": sum(1 for profile in serialised_profiles if profile["model_serving"]),
        "agent_tool_use_repos": sum(1 for profile in serialised_profiles if profile["agent_tool_use"]),
        "repo_profiles": serialised_profiles,
    }
