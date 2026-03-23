from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
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

_TOPIC_CALL_RE = re.compile(
    r"""(?ix)
    \b(?:publish|produce|send|emit|subscribe|consume|listen)\s*
    \(?\s*["']([A-Za-z0-9._-]{2,120})["']
    """
)

_URL_RE = re.compile(r"""https?://([A-Za-z0-9._:-]+)""", re.IGNORECASE)
_PY_IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z0-9_.,\s]+)", re.MULTILINE)
_PY_FROM_RE = re.compile(r"^\s*from\s+([A-Za-z0-9_\.]+)\s+import\s+", re.MULTILINE)
_JS_IMPORT_RE = re.compile(r"""import\s+(?:[^'"]+?\s+from\s+)?['"]([^'"]+)['"]""")
_JS_REQUIRE_RE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_DB_ACCESS_RE = re.compile(
    r"""(?ix)
    \b(
        select\s+.+\s+from|
        insert\s+into|
        update\s+\w+\s+set|
        delete\s+from|
        session\.query|
        create_engine\(
        psycopg2|
        sqlalchemy|
        sqlite3\b|
        pymongo\b|
        mongodb\b|
        jdbc:|
        entitymanager\b|
        db\.query\(
    )
    """
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


_SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    "coverage",
}


def _interesting_repo_files(root: Path) -> tuple[set[str], dict[str, str]]:
    names: set[str] = set()
    contents: dict[str, str] = {}
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.is_dir():
            continue
        rel = path.relative_to(root).as_posix()
        names.add(rel)
        lower = rel.lower()
        should_read = (
            path.suffix.lower() in {".json", ".toml", ".txt", ".py", ".xml", ".gradle", ".kts", ".yaml", ".yml", ".mod", ".csproj", ".props", ".md", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".proto", ".tf"}
            or path.name.lower() in {"dockerfile", "jenkinsfile", "security.md", "license", "license.md", "readme", "readme.md", "chart.yaml", "bitbucket-pipelines.yml", "azure-pipelines.yml", ".nvmrc", "runtime.txt", "codeowners"}
            or ".github/workflows/" in lower
        )
        if should_read:
            try:
                if path.stat().st_size <= 250_000:
                    contents[rel] = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
    return names, contents


def _content_matches(contents: dict[str, str], pattern: str) -> bool:
    regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    return any(regex.search(text) for text in contents.values())


def _extract_first(contents: dict[str, str], pattern: str) -> str:
    regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    for text in contents.values():
        match = regex.search(text)
        if match:
            return str(match.group(1)).strip()
    return ""


def _codeowners_owner(contents: dict[str, str]) -> str:
    for path, text in contents.items():
        if Path(path).name.upper() != "CODEOWNERS":
            continue
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            owners = [part for part in parts[1:] if part.startswith("@") or "@" in part]
            if owners:
                return owners[0]
    return ""


def _major_version(value: str) -> int | None:
    match = re.search(r"(\d+)", str(value or ""))
    return int(match.group(1)) if match else None


def _normalize_runtime_version(runtime: str, version: str) -> str:
    text = str(version or "").strip()
    major = _major_version(text)
    if runtime == "Python":
        if major is None:
            return text
        minor_match = re.search(r"(\d+)\.(\d+)", text)
        if minor_match:
            return f"{minor_match.group(1)}.{minor_match.group(2)}"
        return str(major)
    if runtime == "Node.js":
        if major is None:
            return text
        if major < 18:
            return "<18"
        if major < 20:
            return "18.x"
        if major < 22:
            return "20.x"
        return f"{major}.x"
    if runtime == "JVM":
        if major is None:
            return text
        if major <= 8:
            return "8"
        if major <= 11:
            return "11"
        if major <= 17:
            return "17"
        return f"{major}+"
    if runtime == "Go":
        if major is None:
            return text
        minor_match = re.search(r"(\d+)\.(\d+)", text)
        if minor_match:
            return f"{minor_match.group(1)}.{minor_match.group(2)}"
        return str(major)
    if runtime == ".NET":
        if major is None:
            return text
        if major < 6:
            return "<6"
        if major < 8:
            return "6-7"
        return f"{major}+"
    return text


def _parse_package_json_dependencies(text: str) -> list[str]:
    try:
        payload = json.loads(text or "{}")
    except Exception:
        return []
    deps: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = payload.get(key) or {}
        if isinstance(values, dict):
            deps.update(str(name).strip() for name in values.keys() if str(name).strip())
    return sorted(deps)


def _parse_requirements_dependencies(text: str) -> list[str]:
    deps: set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = re.split(r"[<>=!~\[\s]", line, maxsplit=1)[0].strip()
        if line:
            deps.add(line)
    return sorted(deps)


def _parse_pyproject_dependencies(text: str) -> list[str]:
    deps: set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip().strip(",")
        if not line or line.startswith("["):
            continue
        if "=" in line and not line.startswith('"') and not line.startswith("'"):
            name = line.split("=", 1)[0].strip().strip('"\'')
        else:
            name = line.strip('"\'')
        name = re.split(r"[<>=!~\[\s]", name, maxsplit=1)[0].strip()
        if name and re.match(r"[A-Za-z0-9_.-]+$", name):
            deps.add(name)
    return sorted(deps)


def _parse_pom_dependencies(text: str) -> list[str]:
    deps = re.findall(r"<artifactId>([^<]+)</artifactId>", str(text or ""), re.IGNORECASE)
    return sorted({dep.strip() for dep in deps if dep.strip() and dep.strip().lower() not in {"project"}})


def _parse_go_mod_dependencies(text: str) -> list[str]:
    deps: set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("module ") or line.startswith("go ") or line.startswith("require (") or line == ")":
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        dep = line.split()[0].strip()
        if dep:
            deps.add(dep)
    return sorted(deps)


def _classify_dependency_scope(name: str) -> str:
    dep = str(name or "").strip().lower()
    if not dep:
        return "external"
    internal_markers = (
        "@cognyte/",
        "cognyte-",
        "cognyte_",
        "cognyte.",
        "bitbucket.cognyte.local/",
        "cognyte.local/",
        "git.cognyte.",
        "cgnt-",
        "cgnt_",
    )
    if dep.startswith(internal_markers):
        return "internal"
    if ".cognyte." in dep or dep.endswith(".cognyte.local") or dep.endswith(".local"):
        return "internal"
    return "external"


def _classify_boundary(host: str) -> str:
    value = str(host or "").strip().lower()
    if not value:
        return ""
    if (
        value.endswith(".local")
        or value.endswith(".internal")
        or ".cognyte." in value
        or value.startswith("localhost")
        or value.startswith("127.0.0.1")
    ):
        return "internal"
    return "external"


def _extract_api_hosts(contents: dict[str, str]) -> tuple[list[str], list[str]]:
    internal: set[str] = set()
    external: set[str] = set()
    for text in contents.values():
        for host in _URL_RE.findall(str(text or "")):
            host = host.strip().lower()
            boundary = _classify_boundary(host)
            if boundary == "internal":
                internal.add(host)
            elif boundary == "external":
                external.add(host)
    return sorted(internal), sorted(external)


def _extract_event_topics(contents: dict[str, str]) -> tuple[list[str], list[str]]:
    produced: set[str] = set()
    consumed: set[str] = set()
    for text in contents.values():
        for match in _TOPIC_CALL_RE.finditer(str(text or "")):
            full = match.group(0).lower()
            topic = str(match.group(1) or "").strip()
            if not topic:
                continue
            if any(token in full for token in ("subscribe", "consume", "listen")):
                consumed.add(topic)
            else:
                produced.add(topic)
    return sorted(produced), sorted(consumed)


def _module_key_for_path(path: str) -> str:
    rel = str(path or "").replace("\\", "/")
    stem = rel.rsplit(".", 1)[0]
    if stem.endswith("/__init__"):
        stem = stem[:-9]
    return stem.replace("/", ".").strip(".")


def _candidate_module_keys(path: str) -> set[str]:
    rel = str(path or "").replace("\\", "/")
    stem = rel.rsplit(".", 1)[0]
    parts = [part for part in stem.split("/") if part]
    keys = {".".join(parts).strip(".")}
    if parts and parts[-1] == "__init__":
        keys.add(".".join(parts[:-1]).strip("."))
    return {key for key in keys if key}


def _resolve_relative_module(current_path: str, target: str) -> str:
    current = Path(str(current_path or "").replace("\\", "/"))
    target_path = Path(str(target or ""))
    resolved = (current.parent / target_path).as_posix()
    while "/../" in resolved:
        resolved = str(Path(resolved).as_posix())
    return resolved.rsplit(".", 1)[0].replace("/", ".").strip(".")


def _detect_internal_import_cycles(names: set[str], contents: dict[str, str]) -> tuple[list[str], list[str]]:
    source_files = sorted(
        name for name in names
        if name.lower().endswith((".py", ".js", ".jsx", ".ts", ".tsx"))
    )
    if not source_files:
        return [], []

    module_to_file: dict[str, str] = {}
    for path in source_files:
        for key in _candidate_module_keys(path):
            module_to_file.setdefault(key, path)

    graph: dict[str, set[str]] = {path: set() for path in source_files}
    for path in source_files:
        text = str(contents.get(path, "") or "")
        lower = path.lower()
        if lower.endswith(".py"):
            for match in _PY_IMPORT_RE.findall(text):
                for part in [item.strip().split(" as ", 1)[0].strip() for item in match.split(",")]:
                    target = module_to_file.get(part)
                    if target and target != path:
                        graph[path].add(target)
            for match in _PY_FROM_RE.findall(text):
                target = module_to_file.get(match)
                if target and target != path:
                    graph[path].add(target)
        else:
            for match in list(_JS_IMPORT_RE.findall(text)) + list(_JS_REQUIRE_RE.findall(text)):
                mod = str(match or "").strip()
                if not mod.startswith("."):
                    continue
                resolved = _resolve_relative_module(path, mod)
                target = module_to_file.get(resolved)
                if target and target != path:
                    graph[path].add(target)

    cycles: set[tuple[str, ...]] = set()
    cycle_nodes: set[str] = set()
    stack: list[str] = []
    active: set[str] = set()
    visited: set[str] = set()

    def _walk(node: str) -> None:
        visited.add(node)
        active.add(node)
        stack.append(node)
        for nxt in sorted(graph.get(node, set())):
            if nxt not in visited:
                _walk(nxt)
            elif nxt in active:
                try:
                    start = stack.index(nxt)
                except ValueError:
                    continue
                cycle = tuple(stack[start:])
                if cycle:
                    rotated = min(tuple(cycle[i:] + cycle[:i]) for i in range(len(cycle)))
                    cycles.add(rotated)
                    cycle_nodes.update(cycle)
        stack.pop()
        active.discard(node)

    for node in source_files:
        if node not in visited:
            _walk(node)

    cycle_labels = [" -> ".join(cycle + (cycle[0],)) for cycle in sorted(cycles)]
    return cycle_labels, sorted(cycle_nodes)


def _is_code_file(path: str) -> bool:
    return str(path or "").lower().endswith((
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".cs", ".kt", ".rb"
    ))


def _path_parts_lower(path: str) -> list[str]:
    return [part.lower() for part in str(path or "").replace("\\", "/").split("/") if part]


def _looks_like_ui_file(path: str) -> bool:
    parts = _path_parts_lower(path)
    return any(
        token in parts
        for token in ("ui", "frontend", "front", "web", "client", "pages", "components", "views")
    )


def _looks_like_db_module(path: str) -> bool:
    parts = _path_parts_lower(path)
    return any(
        token in parts
        for token in ("db", "database", "repository", "repositories", "dao", "model", "models", "migration", "migrations", "store")
    )


def _looks_like_service_module(path: str) -> bool:
    parts = _path_parts_lower(path)
    return any(
        token in parts
        for token in ("service", "services", "api", "controller", "controllers", "handler", "handlers", "route", "routes")
    )


def _detect_hardcoded_service_calls(contents: dict[str, str]) -> list[str]:
    examples: list[str] = []
    for path, text in sorted(contents.items()):
        if not _is_code_file(path):
            continue
        for host in _URL_RE.findall(str(text or "")):
            host = str(host or "").strip().lower()
            if not host:
                continue
            examples.append(f"{path} -> {host}")
            if len(examples) >= 8:
                return examples
    return examples


def _detect_db_layer_violations(contents: dict[str, str]) -> tuple[list[str], list[str]]:
    wrong_module_examples: list[str] = []
    layer_violation_examples: list[str] = []
    for path, text in sorted(contents.items()):
        if not _is_code_file(path):
            continue
        if not _DB_ACCESS_RE.search(str(text or "")):
            continue
        is_db_module = _looks_like_db_module(path)
        if not is_db_module:
            wrong_module_examples.append(path)
        if _looks_like_ui_file(path):
            layer_violation_examples.append(path)
        if len(wrong_module_examples) >= 8 and len(layer_violation_examples) >= 8:
            break
    return wrong_module_examples[:8], layer_violation_examples[:8]


def collect_repo_facts(
    repo_root: str | Path,
    repo: str,
    findings: list[dict[str, Any]] | None = None,
    repo_owner: str = "",
    repo_governance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = Path(repo_root)
    names, contents = _interesting_repo_files(root)
    lower_names = {name.lower() for name in names}
    name_string = "\n".join(sorted(lower_names))

    technologies: list[str] = []
    runtimes: list[str] = []
    runtime_versions: dict[str, str] = {}
    iac_tools: list[str] = []
    cloud_platforms: list[str] = []
    api_types: list[str] = []
    event_systems: list[str] = []
    api_boundaries: list[str] = []
    internal_api_hosts: list[str] = []
    external_api_hosts: list[str] = []
    produced_topics: list[str] = []
    consumed_topics: list[str] = []
    ci_systems: list[str] = []
    dependency_files: list[str] = []
    dependency_names: set[str] = set()
    internal_dependency_names: set[str] = set()
    external_dependency_names: set[str] = set()

    has_package_json = "package.json" in lower_names
    has_pyproject = "pyproject.toml" in lower_names
    has_requirements = any(name.endswith("requirements.txt") for name in lower_names)
    has_pom = "pom.xml" in lower_names
    has_gradle = any(name.endswith("build.gradle") or name.endswith("build.gradle.kts") for name in lower_names)
    has_go = "go.mod" in lower_names or any(name.endswith(".go") for name in lower_names)
    has_dotnet = any(name.endswith(".csproj") or name.endswith(".sln") for name in lower_names)

    if has_package_json:
        runtimes.append("Node.js")
        dependency_files.append("package.json")
    if has_pyproject or has_requirements or any(name.endswith(".py") for name in lower_names):
        runtimes.append("Python")
        if has_pyproject:
            dependency_files.append("pyproject.toml")
        if has_requirements:
            dependency_files.append("requirements.txt")
    if has_pom or has_gradle or any(name.endswith(".java") or name.endswith(".kt") for name in lower_names):
        runtimes.append("JVM")
        if has_pom:
            dependency_files.append("pom.xml")
        if has_gradle:
            dependency_files.append("build.gradle")
    if has_go:
        runtimes.append("Go")
        if "go.mod" in lower_names:
            dependency_files.append("go.mod")
    if has_dotnet:
        runtimes.append(".NET")
        dependency_files.append(".csproj")

    package_json = contents.get("package.json", "")
    dependency_names.update(_parse_package_json_dependencies(package_json))
    if re.search(r'"react"\s*:', package_json, re.IGNORECASE) or _content_matches(contents, r"\bfrom ['\"]react['\"]|\breact-dom\b"):
        technologies.append("React")
    if "angular.json" in lower_names or re.search(r"@angular/core", package_json, re.IGNORECASE):
        technologies.append("Angular")
    if re.search(r"spring-boot", "\n".join(contents.values()), re.IGNORECASE):
        technologies.append("Spring Boot")
    if "manage.py" in lower_names or _content_matches(contents, r"\bdjango\b"):
        technologies.append("Django")
    if has_go:
        technologies.append("Go")
    if has_package_json:
        technologies.append("Node.js")
    if has_dotnet:
        technologies.append(".NET")

    python_version = (
        _extract_first(contents, r"requires-python\s*=\s*[\"']([^\"']+)[\"']")
        or _extract_first(contents, r"python(?:-version)?\s*[:=]\s*[\"']?([0-9][^\"'\s]+)")
        or _extract_first(contents, r"python:([0-9][0-9.\-]+)")
    )
    node_version = (
        _extract_first({"package.json": package_json}, r'"node"\s*:\s*"([^"]+)"')
        or contents.get(".nvmrc", "").strip()
        or _extract_first(contents, r"node:([0-9][0-9.\-]+)")
    )
    java_version = (
        _extract_first(contents, r"<java\.version>([^<]+)</java\.version>")
        or _extract_first(contents, r"<maven\.compiler\.(?:source|target)>([^<]+)</maven\.compiler\.(?:source|target)>")
        or _extract_first(contents, r"sourceCompatibility\s*=\s*[\"']?([^\"'\n]+)")
        or _extract_first(contents, r"temurin:([0-9][0-9.\-]+)")
    )
    go_version = _extract_first(contents, r"^go\s+([0-9.]+)$")
    dotnet_version = _extract_first(contents, r"<TargetFramework(?:s)?>([^<]+)</TargetFramework(?:s)?>")
    dependency_names.update(_parse_requirements_dependencies("\n".join(text for path, text in contents.items() if path.lower().endswith("requirements.txt"))))
    if has_pyproject:
        dependency_names.update(_parse_pyproject_dependencies(contents.get("pyproject.toml", "")))
    if has_pom:
        dependency_names.update(_parse_pom_dependencies(contents.get("pom.xml", "")))
    if "go.mod" in lower_names:
        dependency_names.update(_parse_go_mod_dependencies(contents.get("go.mod", "")))
    for runtime, version in (
        ("Python", python_version),
        ("Node.js", node_version),
        ("JVM", java_version),
        ("Go", go_version),
        (".NET", dotnet_version),
    ):
        if version:
            runtime_versions[runtime] = _normalize_runtime_version(runtime, version)

    if any(name.endswith(".tf") for name in lower_names):
        iac_tools.append("Terraform")
    if "chart.yaml" in lower_names:
        iac_tools.append("Helm")
    if _content_matches(contents, r"AWSTemplateFormatVersion|AWS::[A-Za-z]+::[A-Za-z]+"):
        iac_tools.append("CloudFormation")
    if _content_matches(contents, r"^\s*kind:\s*(Deployment|StatefulSet|DaemonSet|Service|Ingress|CronJob)\b"):
        iac_tools.append("Kubernetes")

    if _content_matches(contents, r"\barn:aws:|aws_|s3://|eks\b|lambda\b|cloudformation\b"):
        cloud_platforms.append("AWS")
    if _content_matches(contents, r"\bgcp\b|google[_ -]?cloud|gke\b|pubsub\b"):
        cloud_platforms.append("GCP")
    if _content_matches(contents, r"\bazure\b|azurerm|aks\b|servicebus\b"):
        cloud_platforms.append("Azure")

    if _content_matches(contents, r"@GetMapping|@PostMapping|@RequestMapping|app\.(get|post|put|delete)\(|router\.(get|post|put|delete)\(|FastAPI\(|APIRouter\(|@app\.route\("):
        api_types.append("REST")
    if _content_matches(contents, r"\bgraphql\b|type\s+Query\s*\{|apollo-server|graphene"):
        api_types.append("GraphQL")
    if any(name.endswith(".proto") for name in lower_names) or _content_matches(contents, r"\bgrpc\b"):
        api_types.append("gRPC")
    if _content_matches(contents, r"\bkafka\b|\brabbitmq\b|\brabbitmq\b|\bnats\b|\bsqs\b|\bsns\b|\bpubsub\b"):
        api_types.append("Event-driven")
    if _content_matches(contents, r"\bkafka\b"):
        event_systems.append("Kafka")
    if _content_matches(contents, r"\brabbitmq\b"):
        event_systems.append("RabbitMQ")
    if _content_matches(contents, r"\bnats\b"):
        event_systems.append("NATS")
    if _content_matches(contents, r"\bsqs\b|\bsns\b"):
        event_systems.append("AWS Messaging")
    if _content_matches(contents, r"\bpubsub\b"):
        event_systems.append("GCP Pub/Sub")
    produced_topics, consumed_topics = _extract_event_topics(contents)
    internal_api_hosts, external_api_hosts = _extract_api_hosts(contents)
    if internal_api_hosts:
        api_boundaries.append("Internal API")
    if external_api_hosts:
        api_boundaries.append("External API")

    has_readme = any(Path(name).name.lower().startswith("readme") for name in lower_names)
    has_license = any(Path(name).name.lower().startswith("license") for name in lower_names)
    has_security = any(Path(name).name.lower() == "security.md" for name in lower_names)
    if "bitbucket-pipelines.yml" in lower_names:
        ci_systems.append("Bitbucket Pipelines")
    if ".gitlab-ci.yml" in lower_names:
        ci_systems.append("GitLab CI")
    if "jenkinsfile" in lower_names:
        ci_systems.append("Jenkins")
    if "azure-pipelines.yml" in lower_names:
        ci_systems.append("Azure Pipelines")
    if any(".github/workflows/" in name for name in lower_names):
        ci_systems.append("GitHub Actions")
    has_ci_pipeline = bool(ci_systems)
    has_tests = (
        any("/tests/" in f"/{name}/" or "/__tests__/" in f"/{name}/" for name in lower_names)
        or any(re.search(r"(^|/)(test_[^/]+|[^/]+\.(spec|test)\.(py|js|ts|tsx|jsx|go|java|cs))$", name) for name in lower_names)
    )
    governance_source = dict(repo_governance or {})
    has_branch_governance = bool(governance_source.get("has_branch_governance"))
    has_review_gate = bool(governance_source.get("has_review_gate"))
    governance = {
        "readme": has_readme,
        "license": has_license,
        "security_md": has_security,
        "ci_pipeline": has_ci_pipeline,
        "tests": has_tests,
    }
    if repo_governance is not None:
        governance["branch_governance"] = has_branch_governance
        governance["review_gate"] = has_review_gate
    missing_governance = [label for label, present in (
        ("README", has_readme),
        ("LICENSE", has_license),
        ("SECURITY.md", has_security),
        ("CI Pipeline", has_ci_pipeline),
        ("Tests", has_tests),
    ) if not present]
    if repo_governance is not None:
        if not has_branch_governance:
            missing_governance.append("Branch Governance")
        if not has_review_gate:
            missing_governance.append("Review Gate")
    codeowners_owner = _codeowners_owner(contents)
    owner = codeowners_owner or str(repo_owner or "").strip()
    owner_label = owner or "Unowned"
    owner_key = owner_label.strip().lower()
    is_orphaned = owner_key in {"", "unknown", "user", "unowned"}

    findings_list = list(findings or [])
    for dependency in dependency_names:
        if _classify_dependency_scope(dependency) == "internal":
            internal_dependency_names.add(dependency)
        else:
            external_dependency_names.add(dependency)
    hardcoded_service_call_examples = _detect_hardcoded_service_calls(contents)
    wrong_module_db_examples, layer_violation_examples = _detect_db_layer_violations(contents)
    import_cycle_examples, cycle_nodes = _detect_internal_import_cycles(names, contents)
    anti_pattern_labels: list[str] = []
    anti_pattern_examples: list[str] = []
    if hardcoded_service_call_examples:
        anti_pattern_labels.append("Hardcoded cross-service calls")
        anti_pattern_examples.extend(hardcoded_service_call_examples[:3])
    if wrong_module_db_examples:
        anti_pattern_labels.append("Direct DB access from the wrong module")
        anti_pattern_examples.extend(f"DB access in {path}" for path in wrong_module_db_examples[:3])
    if layer_violation_examples:
        anti_pattern_labels.append("Layer violations")
        anti_pattern_examples.extend(f"UI talks to DB in {path}" for path in layer_violation_examples[:3])
    if import_cycle_examples:
        anti_pattern_labels.append("Circular builds")
        anti_pattern_examples.extend(import_cycle_examples[:2])
    if len(internal_dependency_names) >= 3:
        anti_pattern_labels.append("Overuse of shared libraries")
        anti_pattern_examples.append(
            "Shared internal libs: " + ", ".join(sorted(internal_dependency_names)[:3])
        )
    ai_profile = build_inventory(findings_list, repo_slugs=[repo])["repo_profiles"][0] if repo else {}
    ai_profile.update(
        {
            "repo": repo,
            "technologies": sorted(set(technologies)),
            "runtimes": sorted(set(runtimes)),
            "runtime_versions": runtime_versions,
            "iac_tools": sorted(set(iac_tools)),
            "cloud_platforms": sorted(set(cloud_platforms)),
            "api_types": sorted(set(api_types)),
            "event_systems": sorted(set(event_systems)),
            "api_boundaries": sorted(set(api_boundaries)),
            "internal_api_hosts": internal_api_hosts,
            "external_api_hosts": external_api_hosts,
            "produced_topics": produced_topics,
            "consumed_topics": consumed_topics,
            "ci_systems": sorted(set(ci_systems)),
            "dependency_files": sorted(set(dependency_files)),
            "dependency_names": sorted(dependency_names),
            "internal_dependency_names": sorted(internal_dependency_names),
            "external_dependency_names": sorted(external_dependency_names),
            "import_cycle_examples": import_cycle_examples[:8],
            "import_cycle_node_count": len(cycle_nodes),
            "has_import_cycles": bool(import_cycle_examples),
            "hardcoded_service_call_examples": hardcoded_service_call_examples[:8],
            "wrong_module_db_examples": wrong_module_db_examples[:8],
            "layer_violation_examples": layer_violation_examples[:8],
            "anti_pattern_labels": anti_pattern_labels,
            "anti_pattern_examples": anti_pattern_examples[:8],
            "governance": governance,
            "missing_governance": missing_governance,
            "has_iac": bool(iac_tools),
            "has_api_surface": bool(api_types),
            "has_branch_governance": has_branch_governance,
            "has_review_gate": has_review_gate,
            "branch_restrictions": int(governance_source.get("branch_restrictions", 0) or 0),
            "default_reviewer_rules": int(governance_source.get("default_reviewer_rules", 0) or 0),
            "owner": owner_label,
            "owner_source": "codeowners" if codeowners_owner else ("repo_metadata" if owner else "none"),
            "is_orphaned": is_orphaned,
        }
    )
    return ai_profile


def build_inventory(findings: list[dict[str, Any]], repo_slugs: list[str] | None = None, repo_facts: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    repo_profiles: dict[str, dict[str, Any]] = {}
    provider_counts: Counter[str] = Counter()
    model_counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    runtime_counts: Counter[str] = Counter()
    technology_counts: Counter[str] = Counter()
    missing_governance_repos = 0
    iac_repos = 0
    api_repos = 0
    boundary_counts: Counter[str] = Counter()
    produced_topic_counts: Counter[str] = Counter()
    consumed_topic_counts: Counter[str] = Counter()
    ci_counts: Counter[str] = Counter()
    branch_governed_repos = 0
    review_gated_repos = 0
    dependency_counts: Counter[str] = Counter()
    internal_dependency_counts: Counter[str] = Counter()
    external_dependency_counts: Counter[str] = Counter()
    internal_dependency_repos = 0

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
    if repo_facts:
        all_repos.update(str(slug) for slug in repo_facts.keys() if slug)

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
        facts = dict((repo_facts or {}).get(repo) or {})
        technologies = sorted(set(facts.get("technologies", []) or []))
        runtimes = sorted(set(facts.get("runtimes", []) or []))
        runtime_versions = dict(facts.get("runtime_versions") or {})
        iac_tools = sorted(set(facts.get("iac_tools", []) or []))
        cloud_platforms = sorted(set(facts.get("cloud_platforms", []) or []))
        api_types = sorted(set(facts.get("api_types", []) or []))
        event_systems = sorted(set(facts.get("event_systems", []) or []))
        api_boundaries = sorted(set(facts.get("api_boundaries", []) or []))
        produced_topics = sorted(set(facts.get("produced_topics", []) or []))
        consumed_topics = sorted(set(facts.get("consumed_topics", []) or []))
        internal_api_hosts = sorted(set(facts.get("internal_api_hosts", []) or []))
        external_api_hosts = sorted(set(facts.get("external_api_hosts", []) or []))
        ci_systems = sorted(set(facts.get("ci_systems", []) or []))
        dependency_files = sorted(set(facts.get("dependency_files", []) or []))
        dependency_names = sorted(set(facts.get("dependency_names", []) or []))
        internal_dependency_names = sorted(set(facts.get("internal_dependency_names", []) or []))
        external_dependency_names = sorted(set(facts.get("external_dependency_names", []) or []))
        governance = dict(facts.get("governance") or {})
        missing_governance = list(facts.get("missing_governance") or [])
        for runtime in runtimes:
            runtime_counts[runtime] += 1
        for tech in technologies:
            technology_counts[tech] += 1
        if missing_governance:
            missing_governance_repos += 1
        if iac_tools:
            iac_repos += 1
        if api_types:
            api_repos += 1
        for boundary in api_boundaries:
            boundary_counts[boundary] += 1
        for topic in produced_topics:
            produced_topic_counts[topic] += 1
        for topic in consumed_topics:
            consumed_topic_counts[topic] += 1
        for ci_system in ci_systems:
            ci_counts[ci_system] += 1
        if facts.get("has_branch_governance"):
            branch_governed_repos += 1
        if facts.get("has_review_gate"):
            review_gated_repos += 1
        for dep in dependency_names:
            dependency_counts[dep] += 1
        if internal_dependency_names:
            internal_dependency_repos += 1
        for dep in internal_dependency_names:
            internal_dependency_counts[dep] += 1
        for dep in external_dependency_names:
            external_dependency_counts[dep] += 1
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
            "technologies": technologies,
            "runtimes": runtimes,
            "runtime_versions": runtime_versions,
            "iac_tools": iac_tools,
            "cloud_platforms": cloud_platforms,
            "api_types": api_types,
            "event_systems": event_systems,
            "api_boundaries": api_boundaries,
            "produced_topics": produced_topics,
            "consumed_topics": consumed_topics,
            "internal_api_hosts": internal_api_hosts,
            "external_api_hosts": external_api_hosts,
            "ci_systems": ci_systems,
            "dependency_files": dependency_files,
            "dependency_names": dependency_names,
            "internal_dependency_names": internal_dependency_names,
            "external_dependency_names": external_dependency_names,
            "governance": governance,
            "missing_governance": missing_governance,
            "has_iac": bool(iac_tools),
            "has_api_surface": bool(api_types),
            "has_branch_governance": bool(facts.get("has_branch_governance")),
            "has_review_gate": bool(facts.get("has_review_gate")),
            "branch_restrictions": int(facts.get("branch_restrictions", 0) or 0),
            "default_reviewer_rules": int(facts.get("default_reviewer_rules", 0) or 0),
            "owner": str(facts.get("owner", "") or ""),
            "owner_source": str(facts.get("owner_source", "") or ""),
            "is_orphaned": bool(facts.get("is_orphaned")),
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
        "runtime_count": len(runtime_counts),
        "technology_count": len(technology_counts),
        "missing_governance_repos": missing_governance_repos,
        "iac_repos": iac_repos,
        "api_repos": api_repos,
        "boundary_by_count": [{"boundary": key, "count": count} for key, count in boundary_counts.most_common()],
        "produced_topics_by_count": [{"topic": key, "count": count} for key, count in produced_topic_counts.most_common()],
        "consumed_topics_by_count": [{"topic": key, "count": count} for key, count in consumed_topic_counts.most_common()],
        "branch_governed_repos": branch_governed_repos,
        "review_gated_repos": review_gated_repos,
        "dependency_count": len(dependency_counts),
        "internal_dependency_repos": internal_dependency_repos,
        "ci_by_count": [{"ci_system": key, "count": count} for key, count in ci_counts.most_common()],
        "dependencies_by_count": [{"dependency": key, "count": count} for key, count in dependency_counts.most_common()],
        "internal_dependencies_by_count": [{"dependency": key, "count": count} for key, count in internal_dependency_counts.most_common()],
        "external_dependencies_by_count": [{"dependency": key, "count": count} for key, count in external_dependency_counts.most_common()],
        "runtimes_by_count": [{"runtime": key, "count": count} for key, count in runtime_counts.most_common()],
        "technologies_by_count": [{"technology": key, "count": count} for key, count in technology_counts.most_common()],
        "repo_profiles": serialised_profiles,
    }
