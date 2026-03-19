"""
HTML Report Generator
AI Security & Compliance Monitoring
"""

import hashlib
import json
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict, Counter
import html as html_mod
from datetime import datetime
from dateutil import tz
from services.inventory import build_inventory
from services.threat_modeling import build_threat_model

SEV_COLOR = {1: "#C00000", 2: "#e05c00", 3: "#c87800", 4: "#5a8a3a"}
SEV_LABEL = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
ISRAEL_TZ = tz.gettz("Asia/Jerusalem")
REPORT_LLM_MAX_FINDINGS = 12
REPORT_LLM_MAX_WORKERS = 3

POLICY_COLOR = {
    "CRITICAL":   "#C00000",
    "BANNED":     "#C00000",
    "RESTRICTED": "#e05c00",
    "REVIEW":     "#c87800",
    "ALLOWED":    "#2e7d32",
    "APPROVED":   "#2e7d32",
}
POLICY_DESC = {
    "CRITICAL":   "Hardcoded secret — rotate immediately.",
    "BANNED":     "Provider is explicitly banned by policy.",
    "RESTRICTED": "Requires explicit approval before use.",
    "REVIEW":     "Not yet assessed — review and document.",
    "APPROVED":   "On the approved provider list.",
    "ALLOWED":    "Matches an internal allowlist entry.",
}

PROVIDER_DISPLAY = {
    # ── Approved AI Tools Registry (official names) ──────────────────
    "microsoft_365_copilot_chat":  "Microsoft 365 Copilot Chat",
    "microsoft_copilot_studio":    "Microsoft Copilot Studio",
    "github_copilot_enterprise":   "GitHub Copilot – Enterprise Edition",
    "openai_enterprise":           "OpenAI API – Enterprise",
    "openai":                      "OpenAI API – Enterprise",
    "chatgpt_enterprise":          "ChatGPT – Enterprise Edition",
    "google_gemini_enterprise":    "Google Gemini – Enterprise Edition",
    "google_ai_studio_enterprise": "Google AI Studio – Enterprise Edition",
    "google_gemini_vertexai":      "Google Gemini – Enterprise Edition",
    "grammarly_enterprise":        "Grammarly – Enterprise Edition",
    "synthesia_enterprise":        "Synthesia – Enterprise Edition",
    "cursor_ai_enterprise":        "Cursor AI – Enterprise Edition",
    "gamma_ai_business":           "Gamma AI – Business Plan",
    "adobe_firefly_enterprise":    "Adobe Firefly – Enterprise Edition",
    "notion_enterprise":           "Notion – Enterprise Edition",
    "anthropic":                   "Anthropic Claude – Enterprise Edition",
    "anthropic_claude_code":       "Anthropic Claude Code – Enterprise Edition",
    # ── Restricted / unapproved providers ────────────────────────────
    "azure_openai":                "Azure OpenAI",
    "cohere":                      "Cohere API",
    "cohere_embeddings":           "Cohere Embeddings",
    "huggingface_hub":             "HuggingFace Hub",
    "hf_embeddings":               "HuggingFace Embeddings",
    "mistral_ai":                  "Mistral AI",
    "groq":                        "Groq API",
    "together_ai":                 "Together AI",
    "direct_http_ai":              "Direct HTTP → AI endpoint",
    "langchain":                   "LangChain",
    "llama_index":                 "LlamaIndex (RAG)",
    "transformers":                "HuggingFace Transformers",
    "vllm":                        "vLLM (local server)",
    "llama_cpp":                   "llama.cpp (local)",
    "ctransformers":               "CTransformers (local)",
    "ollama":                      "Ollama (local LLM)",
    "exllamav2":                   "ExLlamaV2 (local)",
    "auto_gptq":                   "AutoGPTQ (quantized)",
    "openai_embeddings":           "OpenAI Embeddings",
    "sentence_transformers":       "Sentence Transformers",
    "google_embeddings":           "Google Embeddings",
    "faiss":                       "FAISS (vector index)",
    "chromadb":                    "ChromaDB",
    "qdrant":                      "Qdrant",
    "weaviate":                    "Weaviate",
    "milvus":                      "Milvus",
    "pgvector":                    "pgvector",
    "elasticsearch_vector":        "Elasticsearch KNN",
    "pinecone":                    "Pinecone",
    "rag_pattern":                 "RAG retrieval pattern",
    "peft_lora":                   "PEFT / LoRA fine-tuning",
    "bitsandbytes":                "bitsandbytes (quantization)",
    "accelerate":                  "HuggingFace Accelerate",
    "trl":                         "TRL (RLHF framework)",
    "transformers_trainer":        "HuggingFace Trainer",
    "generic_finetune":            "Fine-tuning script",
    "pytorch":                     "PyTorch",
    "tensorflow":                  "TensorFlow",
    "scikit_learn":                "scikit-learn",
    "xgboost":                     "XGBoost",
    "lightgbm":                    "LightGBM",
    "hardcoded_key":               "Hardcoded API key / secret",
    "openai_key_pattern":          "OpenAI key pattern (sk-...)",
    "anthropic_key_pattern":       "Anthropic key pattern (sk-ant-...)",
    "prompt_injection_risk":       "Prompt injection risk",
    "logging_risk":                "Prompt/response logging risk",
    "unsafe_code_exec":            "Unsafe code execution near AI",
    "sql_injection_risk":          "LLM-generated SQL injection risk",
    "weak_config":                 "Weak AI config (unbounded tokens)",
    "debug_mode":                  "Debug mode in production",
    "notebook_output_secret":      "Secret in notebook output",
    # Enhancement patterns
    "entropy_secret":              "High-entropy secret (unknown format)",
    "dynamic_import_ai":           "Dynamic AI import (importlib)",
    "dynamic_require_ai":          "Dynamic AI require() call",
    "dynamic_attr_ai":             "Dynamic attribute access on AI client",
    "file_content_to_llm":         "File content → LLM (exfil risk)",
    "dataframe_to_llm":            "DataFrame → LLM (exfil risk)",
    "env_vars_to_llm":             "Env variables → LLM (exfil risk)",
    "db_results_to_llm":           "DB query results → LLM (exfil risk)",
    "http_response_to_llm":        "HTTP response → LLM (injection risk)",
    "unsafe_torch_load":           "Unsafe torch.load() (no weights_only)",
    "unsafe_pickle_model":         "Unsafe pickle/joblib model load",
    "remote_model_load":           "Remote model load via from_pretrained()",
    "unsafe_tf_load":              "Unsafe TensorFlow model load",
    # Task 4: history findings
    "cross_file_secret":           "Cross-file secret import",
    # Task 5: cross-file
    "minified_bundle_secret":      "Hardcoded key in minified bundle",
    # Task 6: minified bundles
    "aws_cdk_ai":                  "AWS AI Service (CDK)",
    "pulumi_ai":                   "Cloud AI Resource (Pulumi)",
    "helm_ai_values":              "AI Config in Helm values",
    "ansible_ai":                  "AI Dependency / Secret (Ansible)",
    "k8s_ai_manifest":             "AI Serving / Secret (Kubernetes)",
    # JS/TS patterns
    "openai_js":                   "OpenAI JS/TS SDK",
    "anthropic_js":                "Anthropic JS/TS SDK",
    "google_ai_js":                "Google AI JS/TS SDK",
    "vercel_ai_sdk":               "Vercel AI SDK",
    "langchain_js":                "LangChain JS/TS",
    "js_env_key_ref":              "API key via process.env",
    "js_hardcoded_key":            "Hardcoded key in JS/TS",
    "nextjs_ai_route":             "Next.js AI route handler",
    # Config patterns
    "env_file_key":                "AI key in .env file",
    "docker_compose_key":          "AI key in docker-compose",
    "terraform_ai_resource":       "Cloud AI resource (Terraform)",
    "k8s_model_serving":           "Model serving (Kubernetes)",
    "dependency_declaration":      "AI library dependency",
    "ci_secret_ref":               "AI key in CI/CD secret",
    "model_name_in_config":        "Hardcoded model name in config",
    # Agent / gateway patterns
    "litellm":                     "LiteLLM proxy/gateway",
    "portkey":                     "Portkey AI gateway",
    "helicone":                    "Helicone observability proxy",
    "autogen":                     "Microsoft AutoGen",
    "crewai":                      "CrewAI agent framework",
    "semantic_kernel":             "Microsoft Semantic Kernel",
    "langgraph":                   "LangGraph (stateful agents)",
    "openai_assistants":           "OpenAI Assistants / Function Calling",
    "nocode_ai_platform":          "No-code AI platform",
    "aws_bedrock":                 "AWS Bedrock",
    "azure_ai_foundry":            "Azure AI Foundry",
    "microsoft_365_copilot_chat":  "Microsoft 365 Copilot Chat",
    "microsoft_copilot_studio":    "Microsoft Copilot Studio",
    "github_copilot_enterprise":   "GitHub Copilot (Enterprise)",
    "chatgpt_enterprise":          "ChatGPT (Enterprise)",
    "grammarly_enterprise":        "Grammarly (Enterprise)",
    "synthesia_enterprise":        "Synthesia (Enterprise)",
    "cursor_ai_enterprise":        "Cursor AI (Enterprise)",
    "gamma_ai_business":           "Gamma AI (Business)",
    "adobe_firefly_enterprise":    "Adobe Firefly (Enterprise)",
    "notion_enterprise":           "Notion (Enterprise)",
}


def fp(raw: str) -> str:
    """Format provider slug → human readable."""
    return PROVIDER_DISPLAY.get(raw, raw.replace("_", " ").title())


class HTMLReporter:

    def __init__(self, output_dir: str, scan_id: str,
                 include_snippets: bool = True, meta: dict = None):
        self.output_dir = Path(output_dir)
        self.scan_id    = scan_id
        self.include_snippets = include_snippets
        self.meta = meta or {}   # repo, project_key, owner, scan_id

    def _llm_cache_path(self) -> Path:
        return self.output_dir / "ai_report_llm_cache.json"

    def _load_llm_cache(self) -> dict[str, str]:
        path = self._llm_cache_path()
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items()}

    def _save_llm_cache(self, cache: dict[str, str]) -> None:
        path = self._llm_cache_path()
        try:
            path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass

    def write(self, findings: List[Dict[str, Any]], policy: dict = None,
              ollama_url: str = "", ollama_model: str = "",
              progress_fn=None, detail_mode: str = "detailed") -> str:
        path = self.output_dir / f"ai_scan_{self.scan_id}.html"
        # Pre-bake LLM detail answers at report-write time if Ollama is available
        llm_details = {}
        if detail_mode == "detailed" and ollama_url and ollama_model:
            try:
                timeout_s = int(self.meta.get("report_detail_timeout_s", 180) or 180)
                llm_details = self._fetch_llm_details(
                    findings, ollama_url.rstrip("/"), ollama_model,
                    progress_fn=progress_fn, timeout=timeout_s)
            except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
                pass  # LLM unavailable — report still generates without answers
        path.write_text(self._render(findings, policy or {}, llm_details),
                        encoding="utf-8")
        return str(path)

    # ── Pre-bake LLM answers at write time ────────────────────────
    def _fetch_llm_details(self, findings: list, base_url: str,
                           model: str, progress_fn=None, timeout: int = 180) -> dict:
        """
        Call Ollama once per finding at report-write time.
        Returns {finding_key: rendered_html_str}.
        Silently stores a placeholder on timeout or error.
        """
        import urllib.request, urllib.error, json as _json, html as _html

        endpoint = base_url + "/api/chat"
        timeout  = max(30, int(timeout or 180))
        results  = {}

        _SYSTEM_PROMPT = (
            "You are a security engineer writing concise, actionable finding reports "
            "for developers. Follow all section headings exactly as instructed. "
            "Return plain text only — no extra commentary before or after the sections."
        )

        def _lang_tag(filename: str) -> str:
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            return {
                "py": "python", "js": "javascript", "ts": "typescript",
                "jsx": "javascript", "tsx": "typescript", "java": "java",
                "go": "go", "rs": "rust", "rb": "ruby", "cs": "csharp",
                "yaml": "yaml", "yml": "yaml", "sh": "bash",
                "tf": "hcl", "json": "json",
            }.get(ext, ext or "text")

        def _build_prompt(f: dict) -> str:
            sev     = {1:"Critical",2:"High",3:"Medium",4:"Low"}.get(
                        f.get("severity", 4), str(f.get("severity", "")))
            cat     = f.get("ai_category", "")
            risk    = f.get("provider_or_lib", "")
            cap     = f.get("capability", "")
            fname   = f.get("file", "")
            line    = f.get("line", "")
            desc    = f.get("description", "")
            snippet = str(f.get("snippet", "") or "")[:300]
            lang    = _lang_tag(fname)
            loc     = f"{fname}:{line}" if line else fname
            return (
                "You are a security engineer. Write a short, structured finding report.\n"
                "RULES:\n"
                "- Use ONLY the four headings below, in order, each on its own line.\n"
                "- Do NOT add any text before the first heading.\n"
                "- Do NOT repeat yourself. Each sentence must be unique.\n"
                "- Stop immediately after the References section.\n\n"
                f"FINDING:\n"
                f"Severity: {sev} | Category: {cat} | Pattern: {risk}\n"
                f"Capability: {cap} | File: {loc}\n"
                + (f"Description: {desc}\n" if desc else "")
                + (f"Snippet:\n```{lang}\n{snippet}\n```\n" if snippet else "")
                + "\n## Why It's Problematic\n"
                "Write 2-3 sentences only. State the attack class (e.g. SQL injection, RCE). "
                "Reference the specific code pattern. Do not repeat.\n\n"
                "## How to Fix It\n"
                "Write exactly 3 bullet points starting with -\n\n"
                "## Secure Code Example\n"
                f"Write one corrected code block fenced with ```{lang}. "
                "Keep it under 15 lines.\n\n"
                "## References\n"
                "Write 1-2 plain HTTPS URLs (OWASP, CWE, or CVE). Then STOP.\n"
            )

        def _render_html(raw: str, placeholder: str = "") -> str:
            """Convert LLM markdown response to safe HTML string."""
            import html as _h, re as _re
            if not raw.strip():
                return (f'<div class="detail-panel">'
                        f'<p style="color:#f97316;font-size:12px">'
                        f'{_h.escape(placeholder)}</p></div>')

            # ── Named section extraction (robust against positional drift) ──
            HEADINGS = [
                ("why",  _re.compile(r'^##\s+why\b',        _re.I)),
                ("fix",  _re.compile(r'^##\s+how\b',        _re.I)),
                ("code", _re.compile(r'^##\s+secure\b',     _re.I)),
                ("refs", _re.compile(r'^##\s+ref',          _re.I)),
            ]
            slots = {"why": [], "fix": [], "code": [], "refs": []}
            current = None
            for line in raw.split("\n"):
                matched = False
                for name, pat in HEADINGS:
                    if pat.match(line.strip()):
                        current = name
                        matched = True
                        break
                if not matched and current:
                    slots[current].append(line)

            def _dedup_sentences(text: str) -> str:
                """Remove repeated sentences (model loop artifact)."""
                seen, out = set(), []
                for sent in _re.split(r'(?<=[.!?])\s+', text.strip()):
                    key = sent.strip().lower()[:80]
                    if key and key not in seen:
                        seen.add(key)
                        out.append(sent)
                return " ".join(out)

            def prose(lines):
                text = _dedup_sentences(" ".join(l for l in lines if l.strip()))
                return (f'<p style="font-size:13px;line-height:1.6;margin:6px 0 12px">'
                        f'{_h.escape(text)}</p>') if text else ""

            def bullets(lines):
                _bullet_re = _re.compile(r'^[\-\*\u2022\u2013\u2014\u00b7]\s+|^\d+[\.\)]\s+')
                # Also strip lines that are ONLY bullet chars / punctuation after stripping
                _debris_re = _re.compile(r'^[\-\*\u2022\u2013\u2014\u00b7\.\,\:\;]+$')
                def _strip(s):
                    # Loop until stable — handles "* - text", "- * text" etc.
                    prev = None
                    while prev != s:
                        prev = s
                        s = _bullet_re.sub("", s).strip()
                    return s
                items = [_strip(l.strip()) for l in lines if l.strip()]
                # Remove empty, single-char, or pure-punctuation debris lines
                items = [i for i in items if i and len(i) > 1 and not _debris_re.match(i)]
                if not items:
                    return prose(lines)
                return ('<ul style="list-style:disc;margin:4px 0 8px 18px;padding:0">'
                        + "".join(f"<li>{_h.escape(i)}</li>" for i in items)
                        + "</ul>")

            def code_block(lines):
                text = "\n".join(lines)
                stripped = _re.sub(r"```[\w]*\n?", "", text).replace("```", "").strip()
                return f"<pre>{_h.escape(stripped)}</pre>" if stripped else ""

            def ref_links(lines):
                links = [l.strip() for l in lines if l.strip().startswith("http")]
                if not links:
                    return prose(lines)
                return "".join(
                    f'<a href="{_h.escape(u)}" target="_blank" '
                    f'style="display:block;font-size:12px;color:var(--pur2);'
                    f'word-break:break-all">{_h.escape(u)}</a>'
                    for u in links)

            why_h  = prose(slots["why"])
            fix_h  = bullets(slots["fix"])
            code_h = code_block(slots["code"])
            ref_h  = ref_links(slots["refs"])

            # Fallback: if named parsing found nothing, try scanning raw for a fenced block
            if not code_h:
                m = _re.search(r"```[\w]*\n(.*?)```", raw, _re.DOTALL)
                if m:
                    code_h = f"<pre>{_h.escape(m.group(1).strip())}</pre>"

            any_c = why_h or fix_h or code_h
            return (
                f'<div class="detail-panel">'
                + (f'<h4>⚠️ Why It\'s Problematic</h4>{why_h}'
                   f'<h4>🔧 How to Fix It</h4>{fix_h}'
                   + (f'<h4>✅ Secure Code Example</h4>{code_h}' if code_h else "")
                   + (f'<h4>📚 References</h4>{ref_h}' if ref_h else "")
                   if any_c else
                   f'<pre style="white-space:pre-wrap;font-size:12px;'
                   f'color:var(--dim)">{_h.escape(raw.strip())}</pre>')
                + "</div>"
            )

        def _key(f: dict) -> str:
            return f"{f.get('file','')}:{f.get('line','')}:{f.get('provider_or_lib','')}"

        def _cache_key(f: dict) -> str:
            material = {
                "model": model,
                "file": f.get("file", ""),
                "line": f.get("line", ""),
                "provider_or_lib": f.get("provider_or_lib", ""),
                "capability": f.get("capability", ""),
                "ai_category": f.get("ai_category", ""),
                "severity": f.get("severity", ""),
                "description": f.get("description", ""),
                "snippet": str(f.get("snippet", "") or "")[:300],
            }
            return hashlib.sha1(
                json.dumps(material, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()

        def _placeholder_html(message: str) -> str:
            return _render_html("", message)

        def _fetch_one(f: dict) -> tuple[str, str]:
            key    = _key(f)
            prompt = _build_prompt(f)
            body   = _json.dumps({
                "model":   model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                "stream":  False,
                "options": {
                    "num_predict":    1024,   # enough for 4 complete sections
                    "num_ctx":        2048,
                    "temperature":    0.1,
                    "repeat_penalty": 1.2,    # prevents repetition loops
                },
            }).encode("utf-8")
            try:
                req  = urllib.request.Request(
                    endpoint,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data    = _json.loads(resp.read().decode("utf-8"))
                    content = (data.get("message") or {}).get("content", "") or \
                              data.get("response", "")
                return key, _render_html(content)
            except (urllib.error.URLError, TimeoutError, OSError, ValueError, _json.JSONDecodeError) as exc:
                return key, _placeholder_html(f"⚠ LLM unavailable ({model}): {exc}")

        limited_findings = list(findings[:REPORT_LLM_MAX_FINDINGS])
        skipped_findings = list(findings[REPORT_LLM_MAX_FINDINGS:])
        for finding in skipped_findings:
            results[_key(finding)] = _placeholder_html(
                f"⚠ LLM analysis skipped for this finding to keep report generation responsive. "
                f"Only the first {REPORT_LLM_MAX_FINDINGS} findings are enriched per report."
            )

        unique_findings: dict[str, dict] = {}
        for finding in limited_findings:
            unique_findings.setdefault(_key(finding), finding)

        work_items = list(unique_findings.values())
        total_work = len(work_items)
        if not work_items:
            return results

        cache = self._load_llm_cache()
        uncached_items: list[dict] = []
        completed = 0
        for finding in work_items:
            key = _key(finding)
            cached_html = cache.get(_cache_key(finding))
            if cached_html:
                results[key] = cached_html
                completed += 1
                if progress_fn:
                    try:
                        progress_fn(completed, total_work, finding.get("capability", finding.get("provider_or_lib", "")))
                    except (TypeError, ValueError):
                        pass
            else:
                uncached_items.append(finding)

        if not uncached_items:
            return results

        max_workers = max(1, min(REPORT_LLM_MAX_WORKERS, len(uncached_items)))
        if max_workers == 1:
            for finding in uncached_items:
                key, html = _fetch_one(finding)
                results[key] = html
                cache[_cache_key(finding)] = html
                completed += 1
                if progress_fn:
                    try:
                        progress_fn(completed, total_work, finding.get("capability", finding.get("provider_or_lib", "")))
                    except (TypeError, ValueError):
                        pass
            self._save_llm_cache(cache)
            return results

        future_meta = {}
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="report-llm") as executor:
            for finding in uncached_items:
                future = executor.submit(_fetch_one, finding)
                future_meta[future] = finding
            for future in as_completed(future_meta):
                finding = future_meta[future]
                key, html = future.result()
                results[key] = html
                cache[_cache_key(finding)] = html
                completed += 1
                if progress_fn:
                    try:
                        progress_fn(completed, total_work, finding.get("capability", finding.get("provider_or_lib", "")))
                    except (TypeError, ValueError):
                        pass
        self._save_llm_cache(cache)
        return results

    def _render(self, findings, policy, llm_details=None):
        llm_details = llm_details or {}
        stats = self._stats(findings)
        delta = self.meta.get("delta", {})
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AI Security &amp; Compliance Monitoring — {self.scan_id}</title>
{self._css()}
{self._config_js(llm_details)}
</head>
<body>
<div class="wrap">
  {self._header(findings)}
  {self._section_delta(findings, delta)}
  {self._section_inventory(findings)}
  {self._section_threat_model(findings)}
  {self._section_summary(stats, findings, policy)}
  {self._section_findings(findings, delta)}
  {self._section_remediation(findings)}
  {self._footer()}
</div>
{self._js()}
</body>
</html>"""

    def _config_js(self, llm_details=None):
        """Embed scan-time config and pre-baked LLM detail answers as JS constants."""
        import json as _json
        llm_info = self.meta.get("llm_model_info") or {}
        model    = llm_info.get("name", "")
        details_json = _json.dumps(llm_details or {})
        return (f'<script>\n'
                f'window.OLLAMA_URL    = "/ollama";\n'
                f'window.OLLAMA_MODEL  = {_json.dumps(model)};\n'
                f'window._LLM_DETAILS  = {details_json};\n'
                f'</script>')

    # ── Stats ──────────────────────────────────────────────────────
    def _stats(self, findings):
        by_sev    = Counter(f["severity"] for f in findings)
        by_cat    = Counter(f.get("ai_category","") for f in findings)
        by_repo   = Counter(f["repo"] for f in findings)
        # repo → project_key mapping
        repo_proj = {f["repo"]: f.get("project_key", "") for f in findings}
        return {
            "total":    len(findings),
            "by_sev":   by_sev,
            "by_cat":   dict(by_cat),
            "by_repo":  dict(by_repo),
            "repo_proj":repo_proj,
            "critical": by_sev.get(1, 0),
            "high":     by_sev.get(2, 0),
            "medium":   by_sev.get(3, 0),
            "low":      by_sev.get(4, 0),
            "repos":    len(by_repo),
            "findings": findings,
        }

    # ── CSS ────────────────────────────────────────────────────────
    def _css(self):
        return """<style>
:root{
  --red:#a2392f;--ora:#e05c00;--yel:#b07a00;--grn:#2e7d32;--lgrn:#4f7b39;
  --pur:#6d3514;--pur2:#8a6c50;--pur3:#f0deca;
  --bg:#f6efe4;--card:#fffaf4;--bdr:#ead4ba;--txt:#261507;--dim:#705333;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);
      color:var(--txt);font-size:14px;line-height:1.5;}
.wrap{max-width:1380px;margin:0 auto;padding:26px 22px;}

/* ══════════════════════════════════════════════════════
   HEADER
   ══════════════════════════════════════════════════════ */
.hdr{
  background:linear-gradient(135deg,#4a210c 0%,#6d3514 55%,#8a6c50 100%);
  border-radius:12px;margin-bottom:18px;overflow:hidden;
  box-shadow:0 4px 20px rgba(74,33,12,.28);
  border:1px solid rgba(255,255,255,.08);
}

/* risk accent bar */
.hdr-accent{height:3px;background:#cda274;}
.hdr.risk-crit .hdr-accent{background:linear-gradient(90deg,#a2392f,#d65b51);}
.hdr.risk-high .hdr-accent{background:linear-gradient(90deg,#d86a00,#f0b24a);}
.hdr.risk-med  .hdr-accent{background:linear-gradient(90deg,#c08a00,#e2c16d);}

/* title band */
.hdr-band{
  display:flex;align-items:center;justify-content:space-between;gap:16px;
  padding:8px 14px 6px;
  border-bottom:1px solid rgba(255,255,255,.1);
}
.hdr-band-copy{display:flex;flex-direction:column;gap:2px}
.hdr-band-title{
  font-size:17px;font-weight:800;color:#fff;
  letter-spacing:-.3px;line-height:1.1;
}
.hdr-band-subtitle{
  font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
  color:rgba(255,255,255,.68);
}

/* body: metadata and stats in a single three-column grid */
.hdr-body{
  display:block;
  padding:0 8px 6px;
}

.hdr-meta{
  width:100%;min-width:0;padding:5px 8px;
  display:grid;grid-template-columns:repeat(3,minmax(0,1fr));
  gap:3px 7px;
  align-items:start;
  border:1px solid rgba(255,255,255,.1);
  border-radius:10px;
  background:rgba(255,255,255,.04);
}
.hdr-meta-item{
  min-width:0;
  display:grid;
  grid-template-columns:auto 1fr;
  column-gap:6px;row-gap:0;align-content:start;
  padding:2px 4px;
  border-radius:10px;
  background:rgba(255,255,255,.03);
}
.hdr-meta-key{
  font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
  color:rgba(255,255,255,.55);white-space:nowrap;padding-top:1px;
}
.hdr-meta-val{
  font-size:11px;font-weight:600;color:rgba(255,255,255,.92);
  white-space:normal;overflow:hidden;text-overflow:ellipsis;
}
.hdr-meta-val.mono{
  font-family:'Cascadia Code',Consolas,monospace;
  font-size:11px;font-weight:400;color:rgba(255,255,255,.78);
}
/* language chips */
.lang-chips{display:flex;flex-wrap:wrap;gap:4px;}
.lang-chip{
  background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.22);
  border-radius:4px;padding:1px 7px;
  font-size:11px;font-weight:600;color:rgba(255,255,255,.88);
  font-family:'Cascadia Code',Consolas,monospace;white-space:nowrap;
}
.hdr-meta-sub{
  display:inline;font-size:11px;font-weight:400;color:rgba(255,255,255,.62);
  margin-left:8px;white-space:nowrap;
}
.hdr-meta-val.s-warn { color:#ffcc80; }
.hdr-meta-val.s-crit { color:#ef9a9a; }
.hdr-meta-val.s-ok   { color:#81c995; }
.hdr-meta-val.s-blue { color:#90caf9; }
@media (max-width:980px){
  .inventory-layout{grid-template-columns:1fr;}
  .hdr-meta{grid-template-columns:repeat(2,minmax(0,1fr));}
}
@media (max-width:720px){
  .hdr-meta{grid-template-columns:1fr;}
  .inventory-grid{grid-template-columns:repeat(2,minmax(0,1fr));}
}

/* ── KPI bar ── */
.kpis{display:flex;gap:13px;flex-wrap:wrap;margin-bottom:26px;}
.kpi{background:var(--card);border-radius:11px;padding:16px 20px;flex:1;
     min-width:120px;box-shadow:0 1px 5px rgba(0,0,0,.07);
      border-top:4px solid var(--pur);}
.kpi.k1{border-color:var(--red);}
.kpi.k2{border-color:var(--ora);}
.kpi.k3{border-color:var(--yel);}
.kpi.k4{border-color:var(--lgrn);}
.kpi .n{font-size:32px;font-weight:700;line-height:1.1;}
.kpi .l{font-size:11px;text-transform:uppercase;letter-spacing:.5px;
         color:var(--dim);margin-top:3px;}

/* ── Cards ── */
.card{background:var(--card);border-radius:11px;padding:20px 24px;
      margin-bottom:20px;box-shadow:0 1px 5px rgba(0,0,0,.07);border:1px solid var(--bdr);}
h2{font-size:19px;font-weight:700;margin:0 0 16px;color:var(--txt);}
h3{font-size:15px;font-weight:600;margin:12px 0 9px;color:var(--txt);}
section{margin-bottom:28px;}

/* ── Tables ── */
table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed;}
th{background:#f0deca;color:#67461f;padding:9px 13px;text-align:left;
   font-size:11px;font-weight:600;text-transform:uppercase;
   letter-spacing:.4px;white-space:nowrap;}
td{padding:8px 13px;border-bottom:1px solid var(--bdr);vertical-align:top;
   word-wrap:break-word;overflow-wrap:break-word;}
tr:nth-child(even) td{background:#fffcf7;}
tr:hover td{background:#f4eadb;}
/* Header repo table — no zebra, no hover highlight */
.hdr tr:nth-child(even) td{background:transparent;}
.hdr tr:hover td{background:transparent;}
.num-cell{text-align:center;font-weight:600;}

/* ── Badges ── */
.b{display:inline-block;padding:2px 8px;border-radius:4px;
   font-size:11px;font-weight:700;letter-spacing:.2px;color:#fff;}
.b1{background:var(--red);}  .b2{background:var(--ora);}
.b3{background:var(--yel);}  .b4{background:var(--lgrn);}
.b-CRITICAL,.b-BANNED{background:var(--red);}
.b-RESTRICTED{background:var(--ora);}
.b-REVIEW{background:var(--yel);}
.b-ALLOWED,.b-APPROVED{background:var(--grn);}

/* ── Policy status cards (summary) ── */
.ps-card{border-radius:8px;padding:7px 12px;flex:1;min-width:100px;
         border:2px solid transparent;text-align:center;}
.ps-card .psc{font-size:20px;font-weight:700;line-height:1.1;}
.ps-card .psl{font-size:10px;font-weight:700;text-transform:uppercase;
              letter-spacing:.5px;margin-top:2px;}
.ps-card .psd{font-size:10px;color:var(--dim);margin-top:3px;line-height:1.3;}

/* ── Provider tags (compact) ── */
.tag-row{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px;}
.tag-a{background:#e8f5e9;border:1px solid #a5d6a7;color:#2e7d32;
       padding:2px 9px;border-radius:12px;font-size:11px;font-weight:500;}
.tag-r{background:#fff3e0;border:1px solid #ffcc80;color:#bf4000;
       padding:2px 9px;border-radius:12px;font-size:11px;font-weight:500;}

/* ── Compact table (summary section) ── */
table.compact{table-layout:fixed;width:100%;}
table.compact th{color:#3f2810;background:#ead3b8;}
table.compact td{padding:2px 8px;border-bottom:1px solid #f0f1f5;overflow:hidden;}
table.compact tr:nth-child(even) td{background:none;}
table.compact tr:hover td{background:#f4eadb;}
table.compact tr:last-child td{border-top:2px solid var(--bdr);border-bottom:none;
                                padding-top:5px;padding-bottom:4px;}

/* ── Sortable column headers ── */
th.sortable{cursor:pointer;user-select:none;white-space:nowrap;}
th.sortable:hover{background:#e4c4a5;}
th.sort-asc::after{content:' ▲';font-size:9px;opacity:.85;}
th.sort-desc::after{content:' ▼';font-size:9px;opacity:.85;}
.snip{background:#18120d;color:#f5debe;padding:9px 13px;border-radius:6px;
      font-family:'Cascadia Code',Consolas,monospace;font-size:11px;
      overflow-x:auto;overflow-y:auto;white-space:pre;
      max-height:180px;min-width:320px;margin-top:5px;display:block;}
.snip-hl{background:#f0b24a;color:#18120d;border-radius:2px;padding:0 1px;
         font-weight:700;}
.fp{font-family:'Cascadia Code',Consolas,monospace;font-size:11px;color:var(--dim);
    overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.fp .snip{white-space:pre;overflow-x:auto;max-width:100%;}

/* ── Clickable finding row ── */
#ft-body tr[data-sev]{cursor:pointer;}
#ft-body tr[data-sev]:hover td{background:#f4eadb !important;}
#ft-body tr.row-expanded td{background:#fbf2e8 !important;}

/* ── Detail panel row ── */
tr.detail-row td{
  padding:0 !important;
  border-bottom:2px solid var(--pur2) !important;
  background:#fbf2e8 !important;
}
tr.detail-row:hover td{background:#fbf2e8 !important;}
.detail-panel{
  padding:18px 24px;
  font-size:13px;line-height:1.65;
  border-left:4px solid var(--pur2);
  background:#fbf2e8;
}
.detail-panel h4{
  font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;
  color:var(--pur2);margin:14px 0 5px;
}
.detail-panel h4:first-child{margin-top:0;}
.detail-panel ul{list-style:disc;margin:4px 0 8px 18px;padding:0;}
.detail-panel li{margin-bottom:3px;}
.scorecard{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
.scorechip{display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:999px;background:#f0deca;border:1px solid var(--bdr);color:#5f3f1c;font-size:11px;font-weight:700}
.inventory-layout{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,.95fr) minmax(0,1.1fr);gap:10px;align-items:start}
.inventory-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;height:100%}
.inventory-card{padding:10px 12px;border:1px solid var(--bdr);border-radius:12px;background:var(--card)}
.inventory-card strong{display:block;font-size:22px;line-height:1.1}
.inventory-list{display:flex;gap:6px;flex-wrap:wrap}
.inventory-chip{display:inline-flex;align-items:center;padding:3px 8px;border-radius:999px;background:#f0deca;border:1px solid var(--bdr);color:#5f3f1c;font-size:11px;font-weight:700}
.inventory-stack{display:grid;gap:10px;height:100%}
.inventory-repos{display:grid;gap:8px;max-height:340px;overflow:auto}
.inventory-repo{padding:9px 11px;border:1px solid var(--bdr);border-radius:12px;background:var(--card);margin-bottom:0}
.inventory-repo-meta{font-size:12px;color:var(--dim);margin-top:4px}
.detail-panel pre{
  display:inline-block;min-width:200px;max-width:100%;
  background:#18120d;color:#f5debe;
  font-family:'Cascadia Code',Consolas,monospace;font-size:11px;
  padding:10px 14px;border-radius:7px;overflow-x:auto;
  margin:6px 0 8px;white-space:pre;
}
.detail-loading{
  display:flex;align-items:center;gap:10px;
  padding:16px 24px;font-size:12px;color:var(--dim);
}
.det-spinner{
  width:16px;height:16px;border-radius:50%;
  border:2px solid var(--bdr);border-top-color:var(--pur2);
  animation:spin .7s linear infinite;flex-shrink:0;
}
@keyframes spin{to{transform:rotate(360deg);}}

/* ── Filter bar ── */
.fbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center;}
.fbar input,.fbar select{padding:6px 10px;border:1px solid var(--bdr);
  border-radius:7px;font-size:12px;background:#fff;color:var(--txt);}
.fbar input:focus,.fbar select:focus{outline:none;border-color:var(--pur2);}

/* ── Remediation ── */
.ri{background:#fbf2e8;border-left:4px solid var(--pur2);
    padding:12px 15px;border-radius:0 8px 8px 0;margin-bottom:10px;}
.ri-ref{font-size:11px;color:var(--dim);margin-bottom:4px;}
.ri-txt{font-size:13px;color:#2d2d2d;line-height:1.6;}

/* ── Footer ── */
.foot{text-align:center;padding:20px;color:var(--dim);font-size:12px;
      border-top:1px solid var(--bdr);margin-top:12px;}

.divider{border:0;border-top:1px solid var(--bdr);margin:14px 0;}
@media(max-width:1100px){.inventory-grid{grid-template-columns:repeat(3,minmax(0,1fr));}}
@media(max-width:700px){.kpis{flex-direction:column;}.inventory-grid{grid-template-columns:repeat(2,minmax(0,1fr));}}

/* ── Tool description popover ── */
.tip-wrap{position:relative;display:inline-block;cursor:default;}
.tip-wrap .tip{
  visibility:hidden;opacity:0;
  position:absolute;z-index:999;left:0;top:calc(100% + 6px);
  width:300px;background:#18120d;color:#f5debe;
  font-size:11px;font-weight:400;line-height:1.55;
  padding:9px 13px;border-radius:7px;
  box-shadow:0 4px 18px rgba(0,0,0,.35);
  white-space:normal;pointer-events:none;
  transition:opacity .15s ease;
}
.tip-wrap:hover .tip{visibility:visible;opacity:1;}

/* ── Pagination controls ── */
#pg-controls button:hover{filter:brightness(0.92);}
#pg-controls button:disabled{opacity:.45;cursor:not-allowed;}


</style>"""

    # ── Header ────────────────────────────────────────────────────
    def _header(self, findings=None):
        findings = findings or []
        commit = html_mod.escape(self.meta.get("commit", ""))
        tool_version = html_mod.escape(self.meta.get("tool_version", ""))
        repo       = html_mod.escape(self.meta.get("repo", "—"))
        project    = html_mod.escape(self.meta.get("project_key", "—"))
        owner_val  = html_mod.escape(self.meta.get("owner", ""))
        branch     = html_mod.escape(self.meta.get("branch", "—")) or "—"
        repos_meta = self.meta.get("repos_meta")   # list of {slug, owner, branch} for multi-repo
        raw_sid  = self.meta.get("scan_id", self.scan_id)
        dur_s    = self.meta.get("scan_duration_s")
        pre_llm  = self.meta.get("pre_llm_count")
        post_llm = self.meta.get("post_llm_count")
        llm_info = self.meta.get("llm_model_info") or {}

        # ── Scan date ─────────────────────────────────────────────
        try:
            dt = datetime.strptime(raw_sid[:15], "%Y%m%d_%H%M%S")
            if ISRAEL_TZ:
                dt = dt.replace(tzinfo=ISRAEL_TZ)
            scan_dt = dt.strftime("%d %b %Y  %H:%M:%S")
        except ValueError:
            scan_dt = raw_sid or "—"

        # ── Duration ──────────────────────────────────────────────
        if dur_s is not None:
            try:
                s = int(dur_s)
                dur_str = f"{s // 60}m {s % 60}s" if s >= 60 else f"{s}s"
            except (TypeError, ValueError):
                dur_str = "—"
        else:
            dur_str = "—"

        # ── LLM model label ───────────────────────────────────────
        if llm_info.get("name"):
            lp = [html_mod.escape(llm_info["name"])]
            if llm_info.get("parameter_size"):
                lp.append(html_mod.escape(llm_info["parameter_size"]))
            if llm_info.get("quantization"):
                lp.append(html_mod.escape(llm_info["quantization"]))
            llm_label = " &thinsp;·&thinsp; ".join(lp)
        else:
            llm_label = None

        # ── 1. Files scanned — derive from findings ───────────────
        # Use unique file paths across all findings
        scanned_files = len({f.get("file", "") for f in findings if f.get("file", "")})
        # If no findings landed, fall back to 0 gracefully
        files_str = str(scanned_files) if scanned_files else "—"

        # ── 3. Policy violations (BANNED + RESTRICTED + CRITICAL) ─
        banned_count     = sum(1 for f in findings
                               if f.get("policy_status","") in ("BANNED","CRITICAL"))
        restricted_count = sum(1 for f in findings
                               if f.get("policy_status","") == "RESTRICTED")
        policy_str  = str(banned_count + restricted_count)
        policy_sub  = []
        if banned_count:
            policy_sub.append(f"{banned_count} banned")
        if restricted_count:
            policy_sub.append(f"{restricted_count} restricted")
        policy_sub_str = "  ·  ".join(policy_sub) if policy_sub else "none"
        policy_cls  = "s-crit" if banned_count else ("s-warn" if restricted_count else "s-ok")

        # ── 4. Languages detected ─────────────────────────────────
        EXT_LANG = {
            ".py":"Python", ".pyw":"Python",
            ".js":"JavaScript", ".mjs":"JavaScript", ".cjs":"JavaScript",
            ".ts":"TypeScript", ".tsx":"TypeScript",
            ".jsx":"JavaScript",
            ".java":"Java", ".kt":"Kotlin", ".scala":"Scala",
            ".go":"Go", ".rb":"Ruby", ".php":"PHP",
            ".cs":"C#", ".cpp":"C++", ".c":"C", ".h":"C/C++",
            ".rs":"Rust", ".swift":"Swift",
            ".sh":"Shell", ".bash":"Shell", ".zsh":"Shell",
            ".yaml":"YAML", ".yml":"YAML",
            ".json":"JSON", ".toml":"TOML", ".env":"Env",
            ".tf":"Terraform", ".hcl":"HCL",
            ".ipynb":"Notebook",
            ".md":"Markdown", ".rst":"reStructuredText",
            ".dockerfile":"Docker", "dockerfile":"Docker",
            ".sql":"SQL",
        }
        lang_set = set()
        for f in findings:
            fp_val = f.get("file", "")
            if fp_val:
                ext = Path(fp_val).suffix.lower()
                name_lower = Path(fp_val).name.lower()
                lang = EXT_LANG.get(name_lower) or EXT_LANG.get(ext)
                if lang:
                    lang_set.add(lang)
        # Sort: common code langs first, then config/infra
        _PRIO = ["Python","JavaScript","TypeScript","Java","Go","C#","C++","Rust",
                 "Kotlin","Ruby","PHP","Scala","Swift","Shell","Notebook",
                 "YAML","JSON","TOML","Env","Terraform","HCL","Docker","SQL",
                 "Markdown","reStructuredText"]
        langs_sorted = sorted(lang_set, key=lambda l: _PRIO.index(l) if l in _PRIO else 99)
        lang_chips_html = "".join(
            f'<span class="lang-chip">{html_mod.escape(l)}</span>'
            for l in langs_sorted
        ) if langs_sorted else '<span class="lang-chip" style="opacity:.45">—</span>'
        # ── 6. LLM dismissal rate ─────────────────────────────────
        if pre_llm and post_llm is not None and pre_llm > 0:
            dismissed     = pre_llm - post_llm
            dismiss_pct   = round(dismissed / pre_llm * 100)
            dismiss_str   = f"{dismiss_pct}%"
            dismiss_sub   = f"{dismissed} of {pre_llm} dismissed"
            dismiss_cls   = "s-ok" if dismiss_pct >= 40 else ("s-blue" if dismiss_pct >= 15 else "s-blue")
        elif pre_llm == 0:
            dismiss_str, dismiss_sub, dismiss_cls = "0%", "no pattern matches", "s-ok"
        else:
            dismiss_str, dismiss_sub, dismiss_cls = "—", "no LLM data", "s-blue"

        # ── Pattern matches tile ──────────────────────────────────
        if pre_llm is not None and post_llm is not None:
            matches_str = str(pre_llm)
            matches_sub = f"→ {post_llm} after LLM review"
        else:
            matches_str = str(len(findings))
            matches_sub = "total findings"

        # ── Risk class for accent bar ─────────────────────────────
        sev_counts = {1: 0, 2: 0, 3: 0, 4: 0}
        for f in findings:
            s = f.get("severity", 4)
            if s in sev_counts:
                sev_counts[s] += 1
        if sev_counts[1]:   risk_cls = "risk-crit"
        elif sev_counts[2]: risk_cls = "risk-high"
        elif sev_counts[3]: risk_cls = "risk-med"
        else:               risk_cls = ""

        # ── Metadata rows ─────────────────────────────────────────
        def mrow(key, val, mono=False, raw=False):
            mono_cls = " mono" if mono else ""
            val_html = val if raw else html_mod.escape(str(val))
            return (
                '<div class="hdr-meta-item">'
                f'<div class="hdr-meta-key">{key}</div>'
                f'<div class="hdr-meta-val{mono_cls}">{val_html}</div>'
                '</div>'
            )

        primary_rows = []
        secondary_rows = []
        stat_rows = []

        if project and project != "—":
            primary_rows.append(mrow("Project", project))
        if repos_meta:
            # Multi-repo: show per-repo table instead of single repo/owner/branch rows
            # Compact dimmed table — no highlight, small font
            # Cell colour: visible on dark purple header but not dominant
            _rc = "rgba(255,255,255,.72)"   # repo/branch — monospace
            _oc = "rgba(255,255,255,.55)"   # owner — softer
            _hc = "rgba(255,255,255,.45)"   # col headers — dimmest
            trows = "".join(
                f"<tr>"
                f"<td style='padding:1px 0 1px 0;font-family:var(--mono);font-size:10px;"
                f"color:{_rc};max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>"
                f"{html_mod.escape(r['slug'])}</td>"
                f"<td style='padding:1px 0 1px 10px;font-size:10px;color:{_oc};"
                f"max-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>"
                f"{html_mod.escape(r.get('owner','—') or '—')}</td>"
                f"<td style='padding:1px 0 1px 10px;font-family:var(--mono);font-size:10px;"
                f"color:{_rc};max-width:90px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>"
                f"{html_mod.escape(r.get('branch','—') or '—')}</td>"
                f"</tr>"
                for r in repos_meta
            )
            repo_table = (
                f"<table style='border-collapse:collapse;margin-top:3px;table-layout:fixed;width:320px'>"
                f"<colgroup>"
                f"<col style='width:130px'><col style='width:100px'><col style='width:90px'>"
                f"</colgroup>"
                f"<thead><tr>"
                f"<th style='padding:0 0 3px;font-size:9px;font-weight:600;"
                f"color:{_hc};text-align:left;text-transform:uppercase;letter-spacing:.04em'>Repo</th>"
                f"<th style='padding:0 0 3px 10px;font-size:9px;font-weight:600;"
                f"color:{_hc};text-align:left;text-transform:uppercase;letter-spacing:.04em'>Owner</th>"
                f"<th style='padding:0 0 3px 10px;font-size:9px;font-weight:600;"
                f"color:{_hc};text-align:left;text-transform:uppercase;letter-spacing:.04em'>Branch</th>"
                f"</tr></thead><tbody>{trows}</tbody></table>"
            )
            primary_rows.append(
                '<div class="hdr-meta-item">'
                f'<div class="hdr-meta-key" style="align-self:start;padding-top:4px">Repositories</div>'
                f'<div class="hdr-meta-val">{repo_table}</div>'
                '</div>'
            )
        else:
            if repo and repo not in ("—", "combined"):
                primary_rows.append(mrow("Repository", repo))
            if owner_val:
                primary_rows.append(mrow("Owner", owner_val))
            branch_commit = branch if branch not in ("—", "") else ""
            if commit:
                branch_commit = f"{branch_commit}/{commit[:12]}" if branch_commit else commit[:12]
            if branch_commit:
                primary_rows.append(mrow("Branch/Commit", branch_commit, mono=True))
        secondary_rows.append(mrow("Scan Date", scan_dt))
        secondary_rows.append(mrow("Duration", dur_str))
        if tool_version:
            secondary_rows.append(mrow("Tool Version", tool_version, mono=True))
        if llm_label:
            secondary_rows.append(mrow("Model Used", llm_label, raw=True))
        secondary_rows.append(
            '<div class="hdr-meta-item">'
            f'<div class="hdr-meta-key">Languages</div>'
            f'<div class="hdr-meta-val"><div class="lang-chips">{lang_chips_html}</div></div>'
            '</div>'
        )
        # ── Stat rows ─────────────────────────────────────────────
        def stat_row(label, val, sub="", extra_cls=""):
            sub_html = f'<div class="hdr-meta-sub">{html_mod.escape(sub)}</div>' if sub else ""
            return (
                '<div class="hdr-meta-item">'
                f'<div class="hdr-meta-key">{label}</div>'
                f'<div class="hdr-meta-val {extra_cls}">{val}{sub_html}</div>'
                '</div>'
            )

        stat_rows.extend([
            stat_row("Files Scanned", files_str, "unique files with findings", "s-blue"),
            stat_row("Pattern Matches", matches_str, matches_sub),
            stat_row("Policy Violations", policy_str, policy_sub_str, policy_cls),
            stat_row("LLM Dismissal Rate", dismiss_str, dismiss_sub, dismiss_cls),
        ])
        meta_rows = "".join(primary_rows + secondary_rows + stat_rows)

        return f"""<div class="hdr {risk_cls}">
  <div class="hdr-accent"></div>
  <div class="hdr-band">
    <div class="hdr-band-copy">
      <div class="hdr-band-title">AI Security &amp; Compliance Scan Report</div>
      <div class="hdr-band-subtitle">Findings summary and detailed evidence</div>
    </div>
  </div>
  <div class="hdr-body">
    <div class="hdr-meta">{meta_rows}</div>
  </div>
</div>"""

    # ── KPI bar ────────────────────────────────────────────────────
    def _kpi_bar(self, stats):
        return f"""<div class="kpis">
  <div class="kpi"><div class="n">{stats['total']}</div><div class="l">Total Findings</div></div>
  <div class="kpi k1"><div class="n" style="color:var(--red)">{stats['critical']}</div><div class="l">Critical</div></div>
  <div class="kpi k2"><div class="n" style="color:var(--ora)">{stats['high']}</div><div class="l">High</div></div>
  <div class="kpi k3"><div class="n" style="color:var(--yel)">{stats['medium']}</div><div class="l">Medium</div></div>
  <div class="kpi k4"><div class="n" style="color:var(--lgrn)">{stats['low']}</div><div class="l">Low</div></div>
</div>"""

    # ── Summary: category + severity+context side by side ─────────
    def _section_summary(self, stats, findings, policy):
        policy = policy or {}   # defensive guard — never let None reach .get() calls
        # Findings by Category
        cat_rows = ""
        for cat, cnt in sorted(stats["by_cat"].items(), key=lambda x: -x[1]):
            pct = int(cnt / stats["total"] * 100) if stats["total"] else 0
            # bar lives in its own cell — clipped to cell width via overflow:hidden
            bar = (f'<div style="background:var(--pur2);height:7px;border-radius:3px;'
                   f'width:{pct}%;min-width:3px;"></div>')
            cat_rows += (
                f"<tr>"
                # col 0: name — fixed width, never grows into bar column
                f"<td style='width:140px;white-space:nowrap;overflow:hidden;"
                f"text-overflow:ellipsis;padding-right:8px'>{html_mod.escape(cat)}</td>"
                # col 1: bar — explicit width, overflow:hidden clips the div
                f"<td style='width:100px;vertical-align:middle;overflow:hidden;"
                f"padding-right:8px'>{bar}</td>"
                # col 2: count
                f"<td class='num-cell' style='width:30px'>{cnt}</td>"
                f"</tr>"
            )
        cat_total = stats["total"]
        cat_rows += (f"<tr style='border-top:2px solid var(--bdr);font-weight:700'>"
                     f"<td>Total</td><td></td>"
                     f"<td class='num-cell'>{cat_total}</td></tr>")

        # Findings by Severity and Context
        # Build (severity, context) → count matrix
        from collections import Counter as _Counter
        sev_ctx_counts = _Counter(
            (f.get("severity", 4), f.get("context", "production"))
            for f in findings
        )
        ctx_order  = ["production", "test", "docs", "deleted_file"]
        ctx_labels = {
            "production":  "Prod",
            "test":        "Test",
            "docs":        "Docs",
            "deleted_file":"Hist",
        }
        ctx_colors = {
            "production":  "var(--txt)",
            "test":        "#9e9e9e",
            "docs":        "#4db6e8",
            "deleted_file":"#b39ddb",
        }
        # only show contexts that have at least one finding
        active_ctxs = [c for c in ctx_order
                       if any(sev_ctx_counts.get((s, c), 0) for s in (1,2,3,4))]

        sev_order = [(1,"Critical","var(--red)"), (2,"High","var(--ora)"),
                     (3,"Medium","var(--yel)"),   (4,"Low","var(--lgrn)")]

        # Column headers always white
        ctx_th = "".join(
            f"<th style='color:#fff;font-size:11px;text-align:center'>"
            f"{ctx_labels[c]}</th>"
            for c in active_ctxs
        )
        sev_rows = ""
        sev_total = 0
        for sev_num, sev_name, color in sev_order:
            row_total = sum(sev_ctx_counts.get((sev_num, c), 0) for c in active_ctxs)
            if not row_total:
                continue
            sev_total += row_total
            badge = f"<span class='b b{sev_num}'>{sev_name}</span>"
            ctx_cells = "".join(
                f"<td class='num-cell' style='color:{ctx_colors[c]}'>"
                f"{sev_ctx_counts.get((sev_num, c), 0) or '—'}</td>"
                for c in active_ctxs
            )
            sev_rows += f"<tr><td>{badge}</td>{ctx_cells}<td class='num-cell'>{row_total}</td></tr>"
        # Totals row
        ctx_totals = "".join(
            f"<td class='num-cell'>{sum(sev_ctx_counts.get((s,c),0) for s in (1,2,3,4))}</td>"
            for c in active_ctxs
        )
        sev_rows += (f"<tr style='border-top:2px solid var(--bdr);font-weight:700'>"
                     f"<td>Total</td>{ctx_totals}"
                     f"<td class='num-cell'>{sev_total}</td></tr>")

        # Prod-only pie chart data (resolve CSS vars to hex for Canvas)
        _sev_hex = {"var(--red)":"#C00000","var(--ora)":"#e05c00",
                    "var(--yel)":"#c87800","var(--lgrn)":"#5a8a3a"}
        prod_counts = {
            sev_num: sev_ctx_counts.get((sev_num, "production"), 0)
            for sev_num, _, _ in sev_order
        }
        prod_total = sum(prod_counts.values())
        pie_js_data = ", ".join(
            f"{{label:'{sev_name}',value:{prod_counts[sev_num]},color:'{_sev_hex.get(color, color)}'}}"
            for sev_num, sev_name, color in sev_order
            if prod_counts[sev_num] > 0
        )

        # Approved AI Tools Registry card
        display_names = policy.get("approved_provider_display_names", {})

        def registry_name(slug: str) -> str:
            return html_mod.escape(
                display_names.get(slug) or PROVIDER_DISPLAY.get(slug)
                or slug.replace("_", " ").title()
            )

        approved_keys = policy.get("approved_providers", [])
        policy_note   = policy.get("notes", "")

        # Map provider slug → favicon domain (Google S2 favicon API)
        PROVIDER_FAVICON = {
            "microsoft_365_copilot_chat":  "microsoft.com",
            "microsoft_copilot_studio":    "microsoft.com",
            "github_copilot_enterprise":   "github.com",
            "openai_enterprise":           "openai.com",
            "openai":                      "openai.com",
            "chatgpt_enterprise":          "openai.com",
            "google_gemini_enterprise":    "google.com",
            "google_ai_studio_enterprise": "aistudio.google.com",
            "google_gemini_vertexai":      "cloud.google.com",
            "grammarly_enterprise":        "grammarly.com",
            "synthesia_enterprise":        "synthesia.io",
            "cursor_ai_enterprise":        "cursor.com",
            "gamma_ai_business":           "gamma.app",
            "adobe_firefly_enterprise":    "adobe.com",
            "notion_enterprise":           "notion.so",
            "anthropic":                   "anthropic.com",
            "anthropic_claude_code":       "anthropic.com",
        }

        seen_set, seen_approved = set(), []
        for k in approved_keys:
            n = registry_name(k)
            if n not in seen_set:
                seen_set.add(n)
                domain = PROVIDER_FAVICON.get(k, "")
                favicon_html = (
                    f'<img src="https://www.google.com/s2/favicons?domain={domain}&sz=16" '
                    f'width="14" height="14" '
                    f'style="vertical-align:middle;margin-right:5px;border-radius:2px;flex-shrink:0" '
                    f'onerror="this.style.display=\'none\'">'
                    if domain else
                    '<span style="display:inline-block;width:14px;height:14px;'
                    'margin-right:5px;flex-shrink:0"></span>'
                )
                seen_approved.append((n, favicon_html))

        if seen_approved:
            approved_items = "".join(
                f'<div style="display:flex;align-items:center;padding:2px 0;'
                f'font-size:11px;color:var(--txt)">{ico}{name}</div>'
                for name, ico in seen_approved
            )
        else:
            approved_items = "<em style='color:var(--dim);font-size:11px'>None defined</em>"

        ciso_note = (
            f'<p style="font-size:13px;color:#1a1a1a;margin:12px 0 0;'
            f'padding-top:10px;border-top:1px solid var(--bdr);line-height:1.6">'
            f'⚠️ &nbsp;{html_mod.escape(policy_note)}</p>'
            if policy_note else ""
        )

        providers_card = f"""<div class="card" style="margin-top:0;padding:12px 16px">
  <div style="font-weight:700;color:var(--grn);margin-bottom:9px;font-size:12px;">
    ✅ Approved AI Tools Registry
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0 20px;">
    {approved_items}
  </div>
  {ciso_note}
</div>"""

        pie_card = f"""<div class="card" style="display:flex;flex-direction:column;padding:16px">
  <h3 style="margin-bottom:12px;font-size:13px;letter-spacing:.2px">Findings by Severity in Prod</h3>
  <div style="display:flex;align-items:center;gap:18px;flex:1">
    <div style="position:relative;width:134px;height:134px;flex-shrink:0">
      <canvas id="sev-pie" width="134" height="134" style="display:block"></canvas>
      <div id="sev-pie-centre" style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;pointer-events:none">
        <div style="font-size:18px;font-weight:800;color:#fff;line-height:1">{prod_total}</div>
        <div style="font-size:8px;color:rgba(255,255,255,.5);margin-top:1px">findings</div>
      </div>
    </div>
    <div id="sev-pie-legend" style="display:flex;flex-direction:column;gap:7px;flex:1;min-width:0"></div>
  </div>
  <script>
  (function(){{
    const data = [{pie_js_data}];
    const total = {prod_total};
    const canvas = document.getElementById('sev-pie');
    const legend = document.getElementById('sev-pie-legend');
    if (!canvas || !total) {{
      document.getElementById('sev-pie-centre').innerHTML = '<span style="font-size:11px;color:var(--dim)">No prod findings</span>';
      return;
    }}

    // Build legend immediately
    data.forEach(d => {{
      if (!d.value) return;
      const pct = Math.round(d.value / total * 100);
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:5px;';
      row.innerHTML = `
        <span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:${{d.color}};flex-shrink:0"></span>
        <span style="font-size:12px;color:#333;white-space:nowrap">${{d.label}}</span>
        <span style="font-size:12px;font-weight:700;color:${{d.color}};white-space:nowrap">${{d.value}}<span style="font-weight:400;color:#888;font-size:11px"> (${{pct}}%)</span></span>`;
      legend.appendChild(row);
    }});

    const ctx = canvas.getContext('2d');
    const W = 134, H = 134, cx = W/2, cy = H/2;
    const R = 54, ir = 31, GAP = 0.025;
    // Label radius = midpoint between inner and outer edge (inside the donut band)
    const LR = (ir + R) / 2;

    function draw(progress) {{
      ctx.clearRect(0, 0, W, H);
      let start = -Math.PI / 2;

      data.forEach(d => {{
        const full  = (d.value / total) * 2 * Math.PI * progress;
        const slice = Math.max(0, full - GAP);
        if (slice <= 0) {{ start += full; return; }}

        ctx.save();
        ctx.shadowColor = 'rgba(0,0,0,0.3)';
        ctx.shadowBlur  = 5;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, R, start + GAP/2, start + GAP/2 + slice);
        ctx.closePath();
        ctx.fillStyle = d.color;
        ctx.fill();
        ctx.restore();

        // % label at midpoint of donut band — only for slices wide enough
        if (progress >= 1 && full > 0.45) {{
          const mid = start + GAP/2 + slice/2;
          const pct = Math.round(d.value / total * 100);
          const lx  = cx + Math.cos(mid) * LR;
          const ly  = cy + Math.sin(mid) * LR;
          ctx.save();
          ctx.textAlign    = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillStyle    = 'rgba(255,255,255,0.95)';
          ctx.font         = 'bold 10px sans-serif';
          ctx.fillText(pct + '%', lx, ly);
          ctx.restore();
        }}

        start += full;
      }});

      // Donut hole
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, ir, 0, 2*Math.PI);
      ctx.fillStyle = '#1e2235';
      ctx.fill();
      ctx.restore();
    }}

    let t = 0;
    const FRAMES = 40;
    function step() {{
      t++;
      const ease = t < FRAMES ? 1 - Math.pow(1 - t/FRAMES, 3) : 1;
      draw(ease);
      if (t < FRAMES) requestAnimationFrame(step);
    }}
    requestAnimationFrame(step);
  }})();
  </script>
</div>"""

        # ── Combined: Findings by Repository × Severity (multi-repo only) ──────
        is_multi_summ = bool(self.meta.get("repos_meta"))
        per_repo_card = ""
        if is_multi_summ:
            from collections import Counter as _C2
            # Build repo → severity → context → count
            by_rsc = {}   # repo → (sev, ctx) → count
            for f in findings:
                r   = f.get("repo","?")
                s   = f.get("severity", 4)
                ctx = f.get("context", "production")
                by_rsc.setdefault(r, {})
                by_rsc[r][(s, ctx)] = by_rsc[r].get((s, ctx), 0) + 1

            # Contexts present
            ctx_order  = ["production","test","docs","deleted_file"]
            ctx_labels = {"production":"Prod","test":"Test","docs":"Docs","deleted_file":"Hist"}
            ctx_colors = {"production":"var(--txt)","test":"#9e9e9e",
                          "docs":"#4db6e8","deleted_file":"#b39ddb"}
            active_ctxs = [c for c in ctx_order
                           if any(by_rsc[r].get((s,c),0)
                                  for r in by_rsc for s in (1,2,3,4))]

            # Header: Repo | Crit | High | Med | Low | Total
            # Each cell shows total count; tooltip shows ctx breakdown
            def _cell(repo, sev_n):
                total_v = sum(by_rsc[repo].get((sev_n, c), 0) for c in ctx_order)
                if not total_v:
                    return "<td style='text-align:center;padding:3px 6px'><span style='color:var(--dim)'>—</span></td>"
                # Build tooltip: "Prod:2 Test:1"
                tip_parts = [f"{ctx_labels[c]}:{by_rsc[repo].get((sev_n,c),0)}"
                             for c in active_ctxs if by_rsc[repo].get((sev_n,c),0)]
                tip = " · ".join(tip_parts)
                badge = (f"<span class='b b{sev_n}' style='font-size:10px;padding:1px 7px'>{total_v}</span>")
                if len(tip_parts) > 1:
                    badge = (f"<span class='tip-wrap'>{badge}"
                             f"<span class='tip'>{html_mod.escape(tip)}</span></span>")
                return f"<td style='text-align:center;padding:3px 6px'>{badge}</td>"

            repo_rows = ""
            for r in sorted(by_rsc, key=lambda x: -(sum(by_rsc[x].values()))):
                total_r = sum(by_rsc[r].values())
                # Context breakdown as small chips below repo name
                ctx_chips = "".join(
                    f"<span style='font-size:9px;color:{ctx_colors[c]};margin-right:5px'>"
                    f"{ctx_labels[c]}:{sum(by_rsc[r].get((s,c),0) for s in (1,2,3,4))}</span>"
                    for c in active_ctxs
                    if sum(by_rsc[r].get((s,c),0) for s in (1,2,3,4)) > 0
                )
                repo_rows += (
                    f"<tr>"
                    f"<td style='font-family:var(--mono);font-size:12px;color:var(--text);"
                    f"padding:4px 16px 4px 0;white-space:nowrap'>"
                    f"{html_mod.escape(r)}"
                    f"<div style='margin-top:1px'>{ctx_chips}</div></td>"
                    + _cell(r, 1) + _cell(r, 2) + _cell(r, 3) + _cell(r, 4)
                    + f"<td class='num-cell' style='font-weight:700;padding:3px 6px'>{total_r}</td>"
                    f"</tr>"
                )
            per_repo_card = f"""<div class="card">
  <h3>Findings by Repository &amp; Severity</h3>
  <table class="compact" style="font-size:13px;width:100%">
    <thead><tr>
      <th style="color:#fff;text-align:left">Repository</th>
      <th style="color:var(--red);text-align:center">Critical</th>
      <th style="color:var(--ora);text-align:center">High</th>
      <th style="color:var(--yel);text-align:center">Medium</th>
      <th style="color:var(--lgrn);text-align:center">Low</th>
      <th class="num-cell" style="color:#fff">Total</th>
    </tr></thead>
    <tbody>{repo_rows}</tbody>
  </table>
</div>"""

        # For multi-repo: 3-col grid — Category | Repo×Sev | Pie
        # For single-repo: 3-col grid — Category | Severity×Context | Pie
        if is_multi_summ:
            grid_html = f"""<div style="display:grid;grid-template-columns:1fr minmax(0,500px) 1fr;gap:18px;margin-bottom:18px;">
  <div class="card">
    <h3>Findings by Category</h3>
    <table class="compact" style="font-size:13px"><colgroup><col style="width:140px"><col style="width:100px"><col style="width:30px"></colgroup><tbody>{cat_rows}</tbody></table>
  </div>
  {per_repo_card}
  {pie_card}
</div>"""
        else:
            # 3-col grid: Category | Severity×Context | Pie
            grid_html = f"""<div style="display:grid;grid-template-columns:1fr minmax(0,500px) 1fr;gap:18px;margin-bottom:18px;">
  <div class="card">
    <h3>Findings by Category</h3>
    <table class="compact" style="font-size:13px"><colgroup><col style="width:140px"><col style="width:100px"><col style="width:30px"></colgroup><tbody>{cat_rows}</tbody></table>
  </div>
  <div class="card">
    <h3>Findings by Severity and Context</h3>
    <table class="compact severity-context-table" style="font-size:13px">
      <thead><tr>
        <th style="color:#fff">Severity</th>{ctx_th}<th class="num-cell" style="color:#fff">Total</th>
      </tr></thead>
      <tbody>{sev_rows}</tbody>
    </table>
  </div>
  {pie_card}
</div>"""

        return f"""<section id="summary">
<h2>🔐 Findings Summary</h2>
{grid_html}
{providers_card}
</section>"""

    # ── K: Executive Summary ───────────────────────────────────────
    def _section_executive(self, stats, findings, delta):
        total  = stats["total"]
        crit   = stats["critical"]
        high   = stats["high"]
        med    = stats["medium"]
        low    = stats["low"]

        # Overall risk score: weighted average (Crit=100, High=70, Med=35, Low=10)
        if total:
            raw_score = (crit*100 + high*70 + med*35 + low*10) / total
            risk_score = min(100, int(raw_score))
        else:
            risk_score = 0

        if risk_score >= 70:
            risk_color, risk_label, risk_icon = "var(--red)",  "High Risk",    "🔴"
        elif risk_score >= 35:
            risk_color, risk_label, risk_icon = "var(--ora)",  "Medium Risk",  "🟠"
        else:
            risk_color, risk_label, risk_icon = "var(--grn)",  "Low Risk",     "🟢"

        # Top 3 risks by severity then count
        from collections import Counter
        top_providers = Counter(
            f.get("provider_or_lib","") for f in findings if f.get("severity",4) <= 2
        ).most_common(3)
        top_html = ""
        for prov, cnt in top_providers:
            top_html += (f"<li><strong>{html_mod.escape(fp(prov))}</strong> "
                         f"— {cnt} critical/high finding{'s' if cnt>1 else ''}</li>")
        if not top_html:
            top_html = "<li style='color:var(--grn)'>No critical or high findings ✓</li>"

        # Test vs production breakdown
        test_count = sum(1 for f in findings if f.get("context") == "test")
        prod_count = total - test_count

        # Delta badge
        delta_html = ""
        if delta.get("has_baseline"):
            new_c = delta.get("new_count", 0)
            fix_c = delta.get("fixed_count", 0)
            delta_html = (
                f"<div style='margin-top:14px;padding:10px 14px;"
                f"background:var(--card2);border-radius:6px;font-size:12px;'>"
                f"<strong>vs last scan:</strong>&nbsp;"
                f"<span style='color:var(--red)'>+{new_c} new</span>&nbsp;&nbsp;"
                f"<span style='color:var(--grn)'>−{fix_c} resolved</span>"
                f"</div>"
            )

        return f"""<section id="executive">
<h2>📊 Executive Summary</h2>
<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:18px;margin-bottom:18px;">
  <div class="card" style="text-align:center;padding:24px 16px">
    <div style="font-size:48px;font-weight:800;color:{risk_color}">{risk_score}</div>
    <div style="font-size:13px;color:var(--dim);margin-top:4px">Risk Score / 100</div>
    <div style="font-size:16px;font-weight:700;margin-top:8px">{risk_icon} {risk_label}</div>
    {delta_html}
  </div>
  <div class="card">
    <h3>Top Risks</h3>
    <ul style="padding-left:18px;margin:0;line-height:2">{top_html}</ul>
    <hr class="divider">
    <div style="font-size:12px;color:var(--dim)">
      Production: <strong>{prod_count}</strong> &nbsp;·&nbsp;
      Test: <strong style="color:var(--dim)">{test_count}</strong>
    </div>
  </div>
  <div class="card">
    <h3>Compliance Status</h3>
    <table style="font-size:12px;width:100%"><tbody>
      <tr><td>🔴 Critical findings</td><td class="num-cell"><strong style="color:var(--red)">{crit}</strong></td></tr>
      <tr><td>🟠 High findings</td><td class="num-cell"><strong style="color:var(--ora)">{high}</strong></td></tr>
      <tr><td>🟡 Medium findings</td><td class="num-cell"><strong style="color:var(--yel)">{med}</strong></td></tr>
      <tr><td>🟢 Low findings</td><td class="num-cell"><strong style="color:var(--lgrn)">{low}</strong></td></tr>
      <tr><td colspan="2"><hr class="divider"></td></tr>
      <tr><td>Total findings</td><td class="num-cell"><strong>{total}</strong></td></tr>
    </tbody></table>
  </div>
</div>
</section>"""

    # ── J: Delta / trend section ───────────────────────────────────
    def _section_delta(self, findings, delta):
        if not delta.get("has_baseline"):
            return ""   # first scan — nothing to compare

        new_c   = delta.get("new_count", 0)
        fix_c   = delta.get("fixed_count", 0)
        unch_c  = delta.get("unchanged_count", 0)
        base_f  = html_mod.escape(delta.get("baseline_file", "previous scan"))
        new_h   = delta.get("new_hashes", set())

        new_rows = ""
        for f in findings:
            if f.get("finding_id", f.get("_hash","")) in new_h:
                sev = f.get("severity", 4)
                new_rows += (
                    f"<tr style='background:rgba(192,0,0,0.08)'>"
                    f"<td><span class='b b{sev}'>{SEV_LABEL.get(sev,str(sev))}</span> "
                    f"<span style='font-size:10px;color:var(--red);font-weight:700'>NEW</span></td>"
                    f"<td>{html_mod.escape(f.get('repo',''))}</td>"
                    f"<td>{html_mod.escape(fp(f.get('provider_or_lib','')))}</td>"
                    f"<td class='fp'>{html_mod.escape(f.get('file',''))} :{f.get('line','')}</td>"
                    f"</tr>"
                )

        table_html = ""
        if new_rows:
            table_html = f"""<table style="margin-top:12px;font-size:12px;width:100%">
  <thead><tr><th>Severity</th><th>Repo</th><th>Tool / Library</th><th>Location</th></tr></thead>
  <tbody>{new_rows}</tbody>
</table>"""

        return f"""<section id="delta">
<h2>📈 Scan Delta — Changes Since Last Scan</h2>
<div class="card">
  <div style="display:flex;gap:32px;align-items:center;flex-wrap:wrap">
    <div style="text-align:center">
      <div style="font-size:32px;font-weight:800;color:var(--red)">{new_c}</div>
      <div style="font-size:12px;color:var(--dim)">New findings</div>
    </div>
    <div style="text-align:center">
      <div style="font-size:32px;font-weight:800;color:var(--grn)">{fix_c}</div>
      <div style="font-size:12px;color:var(--dim)">Resolved</div>
    </div>
    <div style="text-align:center">
      <div style="font-size:32px;font-weight:800;color:var(--dim)">{unch_c}</div>
      <div style="font-size:12px;color:var(--dim)">Unchanged</div>
    </div>
    <div style="font-size:11px;color:var(--dim);margin-left:auto">
      Compared to: <code>{base_f}</code>
    </div>
  </div>
  {table_html}
</div>
</section>"""

    # ── Policy (removed — content moved to summary) ────────────────
    def _section_policy(self, findings, policy):
        return ""

    def _section_inventory(self, findings):
        inventory = self.meta.get("inventory") or build_inventory(findings)
        if not inventory.get("repos_total", 0):
            return ""
        provider_chips = "".join(
            f'<span class="inventory-chip">{html_mod.escape(item.get("label", ""))} {item.get("count", 0)}</span>'
            for item in list(inventory.get("providers_by_count") or [])[:8]
        ) or "<span class='muted'>No providers detected.</span>"
        model_chips = "".join(
            f'<span class="inventory-chip">{html_mod.escape(item.get("model", ""))}</span>'
            for item in list(inventory.get("models_by_count") or [])[:8]
        ) or "<span class='muted'>No models detected.</span>"
        repo_cards = "".join(
            f'<div class="inventory-repo"><strong>{html_mod.escape(profile.get("repo", ""))}</strong>'
            f'<div class="inventory-repo-meta">{html_mod.escape(", ".join(profile.get("provider_labels", [])[:4]) or "No provider detail")}</div>'
            f'<div class="inventory-repo-meta">Embeddings / Vector DB: {"Yes" if profile.get("embeddings_vector_db") else "No"}'
            f' · Prompt Handling: {"Yes" if profile.get("prompt_handling") else "No"}'
            f' · Model Serving: {"Yes" if profile.get("model_serving") else "No"}'
            f' · Agent / Tool Use: {"Yes" if profile.get("agent_tool_use") else "No"}</div></div>'
            for profile in list(inventory.get("repo_profiles") or [])[:12]
        )
        return f"""<section id="inventory">
<h2>🧭 AI Inventory</h2>
<div class="inventory-layout">
  <div class="inventory-grid">
    <div class="inventory-card"><div class="muted">Repos Using AI</div><strong>{inventory.get("repos_using_ai_count", 0)} / {inventory.get("repos_total", 0)}</strong></div>
    <div class="inventory-card"><div class="muted">Providers</div><strong>{inventory.get("provider_count", 0)}</strong></div>
    <div class="inventory-card"><div class="muted">Models</div><strong>{inventory.get("model_count", 0)}</strong></div>
    <div class="inventory-card"><div class="muted">Embeddings / Vector DB</div><strong>{inventory.get("embeddings_vector_db_repos", 0)}</strong></div>
    <div class="inventory-card"><div class="muted">Prompt Handling</div><strong>{inventory.get("prompt_handling_repos", 0)}</strong></div>
    <div class="inventory-card"><div class="muted">Model Serving / Agent Use</div><strong>{inventory.get("model_serving_repos", 0)} / {inventory.get("agent_tool_use_repos", 0)}</strong></div>
  </div>
  <div class="card inventory-stack" style="margin-bottom:0">
    <div>
      <h3>Providers</h3>
      <div class="inventory-list">{provider_chips}</div>
    </div>
    <div>
      <h3>Models</h3>
      <div class="inventory-list">{model_chips}</div>
    </div>
  </div>
  <div class="card inventory-stack" style="margin-bottom:0">
    <h3>Repository Profiles</h3>
    <div class="inventory-repos">{repo_cards or "<p class='muted'>No repository profiles available.</p>"}</div>
  </div>
</div>
</section>"""

    def _threat_model_data(self, findings):
        return build_threat_model(findings, meta=self.meta)

    def _section_threat_model(self, findings):
        model = self._threat_model_data(findings)
        architecture = dict(model.get("stages", {}).get("architecture", {}))
        threats = list(model.get("stages", {}).get("threats", []))
        gaps = list(model.get("stages", {}).get("gaps", []))
        attack_trees = list(model.get("stages", {}).get("attack_trees", []))
        assets = list(model.get("stages", {}).get("assets", []))

        def chips(items):
            return "".join(f'<span class="inventory-chip">{html_mod.escape(str(item))}</span>' for item in items) or "<span class='muted'>No observed signals.</span>"

        def entity_list(items):
            return "".join(
                f"<li><strong>{html_mod.escape(str(item.get('name', '')))}</strong>"
                f"<span class='muted'> · {html_mod.escape(str(item.get('kind', '')))}</span></li>"
                for item in items
            ) or "<li class='muted'>No elements inferred.</li>"

        scenario_rows = "".join(
            "<tr>"
            f"<td><div style='font-weight:700'>{html_mod.escape(item['title'])}</div>"
            f"<div class='muted' style='font-size:11px'>{html_mod.escape(item['stride'])}</div></td>"
            f"<td><span class='pill'>{html_mod.escape(item['severity'])}</span></td>"
            f"<td>{html_mod.escape(item['source'])}<br><span class='muted'>to {html_mod.escape(item['target'])}</span></td>"
            f"<td>{html_mod.escape(str(item.get('evidence', {}).get('file', '')))}"
            f"{':' + html_mod.escape(str(item.get('evidence', {}).get('line', ''))) if item.get('evidence', {}).get('line') else ''}</td>"
            f"<td>{html_mod.escape(item['description'])}</td>"
            f"<td>{html_mod.escape('; '.join(item.get('mitigations', [])))}</td>"
            "</tr>"
            for item in threats[:6]
        )
        scenarios_block = (
            '<div class="card inventory-stack" style="margin-bottom:0">'
            '<h3 style="margin:0 0 10px">Threat Scenarios</h3>'
            '<div class="table-shell threat-table-shell"><table>'
            '<thead><tr><th>Threat</th><th>Severity</th><th>Flow</th><th>Evidence</th><th>Description</th><th>Recommended Controls</th></tr></thead>'
            f'<tbody>{scenario_rows}</tbody></table></div></div>'
            if scenario_rows
            else "<div class='card'><div class='muted'>No threats inferred from the current scan.</div></div>"
        )

        gap_items = "".join(f"<li>{html_mod.escape(item)}</li>" for item in gaps)
        attack_tree_cards = "".join(
            '<div class="card inventory-stack" style="margin-bottom:0">'
            f'<h3 style="margin:0">{html_mod.escape(tree["title"])}</h3>'
            f'<div class="muted" style="font-size:12px">{html_mod.escape(tree["root"])}</div>'
            '<ol style="margin:6px 0 0;padding-left:18px;line-height:1.6">'
            + "".join(f"<li>{html_mod.escape(step)}</li>" for step in tree.get("paths", []))
            + "</ol></div>"
            for tree in attack_trees
        ) or "<div class='card'><div class='muted'>No attack trees generated.</div></div>"

        replay_note = (
            f"<div class='warn-box' style='margin-top:10px'>Replay instructions applied: {html_mod.escape(model.get('replay_instructions', ''))}</div>"
            if model.get("replay_instructions")
            else ""
        )

        overview_cards = "".join([
            f'<div class="trend-summary-card threat-overview-card"><span class="baseline-label">Observed Signals</span><strong>{len(list(architecture.get("observed_signals", [])))}</strong></div>',
            f'<div class="trend-summary-card threat-overview-card"><span class="baseline-label">Assets</span><strong>{len(assets)}</strong></div>',
            f'<div class="trend-summary-card threat-overview-card"><span class="baseline-label">Threats</span><strong>{len(threats)}</strong></div>',
            f'<div class="trend-summary-card threat-overview-card"><span class="baseline-label">Gaps</span><strong>{len(gaps)}</strong></div>',
        ])

        return f"""<section id="threat-model">
<h2>🛡️ Threat Model</h2>
<div class="trend-summary-grid threat-overview-grid">
  {overview_cards}
</div>
<div class="threat-support-grid">
  <div class="card inventory-stack threat-signals-card" style="margin-bottom:0">
    <div class="threat-chip-group">
      <h3>Observed Signals</h3>
      <div class="inventory-list">{chips(architecture.get("observed_signals", []))}</div>
    </div>
    <div class="threat-chip-group">
      <h3>Assets at Risk</h3>
      <div class="inventory-list">{chips(assets)}</div>
    </div>
    <div class="threat-chip-group">
      <h3>Trust Boundaries</h3>
      <div class="inventory-list">{chips(item.get("name", "") for item in architecture.get("boundaries", []))}</div>
    </div>
    <div class="threat-chip-group">
      <h3>Flows</h3>
      <div class="inventory-list">{chips(item.get("name", "") for item in architecture.get("flows", [])[:6])}</div>
    </div>
  </div>
  <div class="inventory-stack threat-detail-stack">
    <details class="card threat-disclosure" open>
      <summary>Architecture Elements</summary>
      <div class="repo-grid cols-3" style="gap:12px">
        <div><strong style="font-size:12px">Actors</strong><ul style="margin:6px 0 0;padding-left:18px;line-height:1.6">{entity_list(architecture.get("actors", []))}</ul></div>
        <div><strong style="font-size:12px">Processes</strong><ul style="margin:6px 0 0;padding-left:18px;line-height:1.6">{entity_list(architecture.get("processes", []))}</ul></div>
        <div><strong style="font-size:12px">Stores</strong><ul style="margin:6px 0 0;padding-left:18px;line-height:1.6">{entity_list(architecture.get("stores", []))}</ul></div>
      </div>
    </details>
    <details class="card threat-disclosure">
      <summary>Review Gaps / Open Questions</summary>
      <ul style="margin:0;padding-left:18px;line-height:1.7">{gap_items}</ul>
    </details>
    <details class="card threat-disclosure">
      <summary>Attack Trees</summary>
      <div class="inventory-stack">{attack_tree_cards}</div>
    </details>
    {replay_note}
    <div class="muted" style="font-size:12px">This threat model is evidence-backed by scan results and repository signals. It is a structured first pass that should be refined during architecture review.</div>
  </div>
</div>
<div class="threat-scenarios-row">
  {scenarios_block}
</div>
</section>"""

    # ── All Findings ───────────────────────────────────────────────
    def _section_findings(self, findings, delta=None):
        new_hashes  = (delta or {}).get("new_hashes", set())
        repo        = html_mod.escape(self.meta.get("repo", ""))
        project     = html_mod.escape(self.meta.get("project_key", ""))
        is_multi    = bool(self.meta.get("repos_meta"))   # multi-repo scan
        title_suffix = f"{project} / {repo}" if project and repo else (project or repo or "")

        sorted_findings = sorted(findings, key=lambda f: (f.get("severity", 4), f.get("repo", "")))

        cats = sorted({f.get("ai_category", "") for f in findings if f.get("ai_category", "")})
        cat_options = "\n".join(
            f'      <option value="{html_mod.escape(c)}">{html_mod.escape(c)}</option>'
            for c in cats
        )

        # Unique risk values for filter dropdown
        risks = sorted({fp(f.get("provider_or_lib", "")) for f in findings
                        if f.get("provider_or_lib", "")})
        risk_options = "\n".join(
            f'      <option value="{html_mod.escape(r)}">{html_mod.escape(r)}</option>'
            for r in risks
        )

        # Context display config
        CTX_LABEL = {
            "production":  ("Prod",    "var(--dim)",  "transparent"),
            "test":        ("Test",    "#9e9e9e",     "rgba(158,158,158,0.12)"),
            "docs":        ("Docs",    "#0277bd",     "rgba(2,119,189,0.12)"),
            "deleted_file":("History", "#7b5ea7",     "rgba(123,94,167,0.12)"),
        }

        def _ctx_badge(ctx: str) -> str:
            label, color, bg = CTX_LABEL.get(ctx, ("?", "var(--dim)", "transparent"))
            return (f"<span style='font-size:10px;font-weight:600;color:{color};"
                    f"background:{bg};border:1px solid {color};border-radius:3px;"
                    f"padding:2px 6px;white-space:nowrap'>{label}</span>")

        rows = ""
        for f in sorted_findings:
            sev      = f.get("severity", 4)
            ctx      = f.get("context", "production")
            is_new   = f.get("finding_id", f.get("_hash", "")) in new_hashes
            risk_val = html_mod.escape(fp(f.get("provider_or_lib", "")))

            # Code snippet
            snip = ""
            if self.include_snippets and f.get("snippet"):
                raw_snippet = str(f["snippet"])[:400]
                match_text  = str(f.get("match", ""))
                esc_snippet = html_mod.escape(raw_snippet)
                if match_text:
                    esc_match   = html_mod.escape(match_text)
                    esc_snippet = esc_snippet.replace(
                        esc_match,
                        f"<mark class='snip-hl'>{esc_match}</mark>", 1,
                    )
                snip = f'<div class="snip">{esc_snippet}</div>'

            # Tool/risk cell — no tooltip (description is shown in the LLM detail panel)
            tool_cell = f"<strong style='font-size:12px'>{risk_val}</strong>"

            row_style = "background:rgba(192,0,0,0.07)" if is_new else ""
            cat_val   = html_mod.escape(f.get("ai_category", ""))

            # Extra data attrs for LLM detail panel — use double-quote delimiters;
            # html_mod.escape converts " → &quot; so values are safe inside "…"
            cap_val     = html_mod.escape(f.get("capability", ""))
            desc_val    = html_mod.escape(f.get("description", ""))   # raw field, not tool_desc
            file_val    = html_mod.escape(f.get("file", ""))
            line_val    = html_mod.escape(str(f.get("line", "")))
            sev_label   = SEV_LABEL.get(sev, str(sev))
            snippet_val = html_mod.escape(str(f.get("snippet", ""))[:300]) if f.get("snippet") else ""
            detector_conf = html_mod.escape(str(f.get("detector_confidence_score", f.get("confidence", 0))))
            prod_rel = html_mod.escape(str(f.get("production_relevance_score", 0)))
            evidence_q = html_mod.escape(str(f.get("evidence_quality_score", 0)))
            llm_conf = html_mod.escape(str(f.get("llm_review_confidence_score", "—") if f.get("llm_review_confidence_score") is not None else "—"))
            overall_sig = html_mod.escape(str(f.get("overall_signal_score", 0)))
            # Key must match _key() in _fetch_llm_details
            llm_key_val = html_mod.escape(
                f"{f.get('file','')}:{f.get('line','')}:{f.get('provider_or_lib','')}")

            # col 0:Severity  col 1:Category  col 2:Potential Risk
            # col 3:Capability  col 4:Context  col 5:File:Line/Code
            repo_val = html_mod.escape(f.get("repo", ""))
            rows += (
                f'<tr data-sev="{sev}" data-ctx="{ctx}" data-cat="{cat_val}"'
                f' data-risk="{risk_val}" data-cap="{cap_val}" data-repo="{repo_val}"'
                f' data-desc="{desc_val}" data-file="{file_val}"'
                f' data-line="{line_val}" data-sevlabel="{sev_label}"'
                f' data-snippet="{snippet_val}" data-llm-key="{llm_key_val}"'
                f' data-detconf="{detector_conf}" data-prodrel="{prod_rel}"'
                f' data-evidence="{evidence_q}" data-llmconf="{llm_conf}"'
                f' data-signal="{overall_sig}"'
                f' onclick="toggleDetail(event,this)"'
                f' style="{row_style}">'
                f"<td style='white-space:nowrap'>"
                f"<span class='b b{sev}'>{sev_label}</span></td>"
                + (f"<td style='font-family:var(--mono);font-size:11px;color:var(--dim);white-space:nowrap'>"
                   f"{html_mod.escape(f.get('repo',''))}</td>"
                   if is_multi else "")
                + f"<td>{html_mod.escape(f.get('ai_category', ''))}</td>"
                f"<td>{tool_cell}</td>"
                f"<td>{html_mod.escape(f.get('capability', ''))}</td>"
                f"<td style='text-align:center'>{_ctx_badge(ctx)}</td>"
                f"<td class='fp'>{html_mod.escape(f.get('file', ''))}"
                f"<span style='color:var(--dim)'> :{f.get('line', '')}</span>"
                f"{snip}</td>"
                + f"</tr>"
            )

        # Repo filter (multi-repo only)
        repo_names = sorted({f.get("repo","") for f in findings if f.get("repo","")})
        repo_options = "\n".join(
            f'      <option value="{html_mod.escape(r)}">{html_mod.escape(r)}</option>'
            for r in repo_names
        )
        repo_filter_html = (
            f'''    <select id="frepo" onchange="ff()">
      <option value="">All Repos</option>
{repo_options}
    </select>'''
            if is_multi else ""
        )

        # Repo column in table (multi-repo only)
        repo_col_header = '<th data-col="6" class="sortable">Repository</th>' if is_multi else ""
        repo_colgroup   = '<col style="width:120px">' if is_multi else ""
        min_width       = "760px" if is_multi else "640px"

        return f"""<section id="findings">
<h2>🗂 All Findings for: {title_suffix} ({len(findings)})</h2>
<div class="card">
  <div class="fbar">
    <input type="text" id="fs" placeholder="🔍 Search..." oninput="ff()">
    <select id="fv" onchange="ff()">
      <option value="">All Severities</option>
      <option value="1">Critical</option>
      <option value="2">High</option>
      <option value="3">Medium</option>
      <option value="4">Low</option>
    </select>
    <select id="fcat" onchange="ff()">
      <option value="">All Categories</option>
{cat_options}
    </select>
    <select id="frisk" onchange="ff()">
      <option value="">All Risks</option>
{risk_options}
    </select>
    <select id="fc" onchange="ff()">
      <option value="">All Contexts</option>
      <option value="production">Production</option>
      <option value="test">Test</option>
      <option value="docs">Docs</option>
      <option value="deleted_file">History (deleted)</option>
    </select>
{repo_filter_html}
  </div>
  <div id="pg-info-top" style="font-size:12px;color:var(--dim);margin-bottom:6px"></div>
  <div style="width:100%;overflow-x:auto">
  <table id="ft" style="width:100%;min-width:{min_width};table-layout:fixed">
    <colgroup>
      <col style="width:90px">
      {repo_colgroup}
      <col style="width:120px">
      <col style="width:17%">
      <col style="width:12%">
      <col style="width:72px">
      <col style="width:auto;min-width:200px">
    </colgroup>
    <thead><tr>
      <th data-col="0" class="sortable" style="white-space:nowrap">Severity</th>
      {repo_col_header}
      <th data-col="1" class="sortable">Category</th>
      <th data-col="2" class="sortable">Potential Risk</th>
      <th data-col="3" class="sortable">Capability</th>
      <th data-col="4" class="sortable" style="text-align:center">Context</th>
      <th data-col="5">File : Line / Code</th>
    </tr></thead>
    <tbody id="ft-body">{rows}</tbody>
  </table>
  </div>
  <div id="pg-controls" style="display:flex;gap:6px;align-items:center;
       flex-wrap:wrap;margin-top:10px;font-size:12px"></div>
</div>
</section>"""

    # ── Remediation ────────────────────────────────────────────────
    def _section_remediation(self, findings):
        # Group by provider_or_lib, keep only Critical+High
        from collections import defaultdict
        groups: dict = defaultdict(list)
        for f in findings:
            if f.get("severity", 4) <= 2:
                groups[f.get("provider_or_lib", "")].append(f)

        items = ""
        # Sort groups: Critical-only first, then by occurrence count desc
        def _group_sort_key(kv):
            fs = kv[1]
            min_sev = min(f.get("severity", 4) for f in fs)
            return (min_sev, -len(fs))

        for lib, fs in sorted(groups.items(), key=_group_sort_key):
            min_sev  = min(f.get("severity", 4) for f in fs)
            count    = len(fs)
            remediation = next((f.get("remediation","") for f in fs if f.get("remediation","")), "")
            description = next((f.get("description","") for f in fs if f.get("description","")), "")
            category    = fs[0].get("ai_category", "")
            capability  = fs[0].get("capability", "")

            # Unique files, sorted, deduplicated
            seen_files: set = set()
            file_items = ""
            for f in sorted(fs, key=lambda x: (x.get("file",""), x.get("line", 0))):
                fkey = f"{f.get('file','')}:{f.get('line','')}"
                if fkey in seen_files:
                    continue
                seen_files.add(fkey)
                sev_f = f.get("severity", 4)
                file_items += (
                    f"<li style='margin-bottom:3px'>"
                    f"<span class='b b{sev_f}' style='font-size:9px;padding:1px 5px'>"
                    f"{SEV_LABEL.get(sev_f,'')}</span> "
                    f"<code style='font-size:11px'>{html_mod.escape(f.get('file',''))}"
                    f" :{f.get('line','')}</code>"
                    f"</li>"
                )

            meta_line = " &nbsp;·&nbsp; ".join(p for p in [
                html_mod.escape(category),
                html_mod.escape(capability),
                f"<strong>{count}</strong> occurrence{'s' if count > 1 else ''}",
            ] if p)

            items += (
                f'<div class="ri">'
                f'<div class="ri-ref" style="margin-bottom:6px">'
                f'<span class="b b{min_sev}">{SEV_LABEL.get(min_sev,"")}</span>'
                f' &nbsp;<strong style="font-size:13px">'
                f'{html_mod.escape(fp(lib))}</strong>'
                f'<span style="font-size:11px;color:var(--dim);margin-left:10px">'
                f'{meta_line}</span>'
                f'</div>'
                + (f'<div class="ri-txt" style="margin-bottom:8px">'
                   f'{html_mod.escape(description)}</div>' if description else '')
                + (f'<div class="ri-txt" style="background:#f0eeff;border-left:3px solid var(--pur2);'
                   f'padding:7px 11px;border-radius:0 6px 6px 0;margin-bottom:8px">'
                   f'<strong>Remediation:</strong> {html_mod.escape(remediation)}</div>'
                   if remediation else '')
                + f'<details style="margin-top:4px">'
                  f'<summary style="font-size:11px;color:var(--dim);cursor:pointer">'
                  f'▸ {len(seen_files)} affected location{"s" if len(seen_files)>1 else ""}</summary>'
                  f'<ul style="margin:6px 0 2px 14px;padding:0;list-style:none">'
                  f'{file_items}</ul>'
                  f'</details>'
                f'</div>'
            )

        if not items:
            items = ("<p style='color:var(--grn);font-weight:600'>"
                     "✓ No critical or high findings require immediate action.</p>")
        return f"""<section id="remediation">
<h2>🔧 Remediation Checklist — Critical &amp; High</h2>
<div class="card">{items}</div>
</section>"""

    # ── Footer ─────────────────────────────────────────────────────
    def _footer(self):
        return (f'<div class="foot">'
                f'AI Security &amp; Compliance Monitoring &nbsp;·&nbsp; '
                f'Scan: {self.scan_id} &nbsp;·&nbsp; Internal use only</div>')

    # ── JS ─────────────────────────────────────────────────────────
    def _js(self):
        return r"""<script>
// ── Pagination + filter engine ───────────────────────────────────
const PAGE_SIZE = 20;
let allRows     = [];
let visRows     = [];
let curPage     = 1;

document.addEventListener('DOMContentLoaded', function(){
  allRows = Array.from(document.querySelectorAll('#ft-body tr[data-sev]'));
  // Wire up sortable headers
  document.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => sortBy(parseInt(th.getAttribute('data-col'))));
  });
  ff();
});

// ── Filter ───────────────────────────────────────────────────────
function ff(){
  const s    = (document.getElementById('fs')     || {value:''}).value.toLowerCase();
  const v    = (document.getElementById('fv')     || {value:''}).value;
  const cat  = (document.getElementById('fcat')   || {value:''}).value;
  const risk = (document.getElementById('frisk')  || {value:''}).value;
  const c    = (document.getElementById('fc')     || {value:''}).value;
  const repo = (document.getElementById('frepo')  || {value:''}).value;

  visRows = allRows.filter(r => {
    const txt     = r.textContent.toLowerCase();
    const sev     = r.getAttribute('data-sev')  || '';
    const ctx     = r.getAttribute('data-ctx')  || '';
    const rowCat  = r.getAttribute('data-cat')  || '';
    const rowRisk = r.getAttribute('data-risk') || '';
    const rowRepo = r.getAttribute('data-repo') || '';
    return (!s    || txt.includes(s))
        && (!v    || sev     === v)
        && (!cat  || rowCat  === cat)
        && (!risk || rowRisk === risk)
        && (!c    || ctx     === c)
        && (!repo || rowRepo === repo);
  });

  allRows.forEach(r => r.style.display = 'none');
  curPage = 1;
  renderPage();
}

// ── Render a single page ─────────────────────────────────────────
function renderPage(){
  const total = visRows.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  curPage     = Math.min(Math.max(1, curPage), pages);

  const start = (curPage - 1) * PAGE_SIZE;
  const end   = Math.min(start + PAGE_SIZE, total);

  allRows.forEach(r => {
    r.style.display = 'none';
    // also hide any open detail row
    const dr = r.nextElementSibling;
    if (dr && dr.classList.contains('detail-row')) dr.style.display = 'none';
  });
  visRows.slice(start, end).forEach(r => {
    r.style.display = '';
    // restore visible detail row if one was open
    const dr = r.nextElementSibling;
    if (dr && dr.classList.contains('detail-row')) dr.style.display = '';
  });

  const info = total === 0
    ? 'No matching findings'
    : `Showing ${start + 1}–${end} of ${total} finding${total !== 1 ? 's' : ''}`;
  ['pg-info-top'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = info;
  });

  const ctrl = document.getElementById('pg-controls');
  if (!ctrl) return;
  ctrl.innerHTML = '';
  if (pages <= 1) return;

  const btnStyle   = 'padding:3px 10px;border-radius:5px;border:1px solid var(--bdr);'
                   + 'background:#fff;cursor:pointer;font-size:12px;';
  const activeStyle = btnStyle + 'background:var(--pur);color:#fff;border-color:var(--pur);';

  const prev = document.createElement('button');
  prev.textContent = '← Prev';
  prev.setAttribute('style', btnStyle);
  prev.disabled = (curPage === 1);
  prev.onclick = () => { curPage--; renderPage(); };
  ctrl.appendChild(prev);

  const WING = 3;
  let lo = Math.max(1, curPage - WING);
  let hi = Math.min(pages, curPage + WING);
  if (lo > 1) {
    ctrl.appendChild(pageBtn(1, btnStyle, activeStyle));
    if (lo > 2) ctrl.appendChild(ellipsis());
  }
  for (let p = lo; p <= hi; p++) ctrl.appendChild(pageBtn(p, btnStyle, activeStyle));
  if (hi < pages) {
    if (hi < pages - 1) ctrl.appendChild(ellipsis());
    ctrl.appendChild(pageBtn(pages, btnStyle, activeStyle));
  }

  const next = document.createElement('button');
  next.textContent = 'Next →';
  next.setAttribute('style', btnStyle);
  next.disabled = (curPage === pages);
  next.onclick = () => { curPage++; renderPage(); };
  ctrl.appendChild(next);

  const info2 = document.createElement('span');
  info2.style.marginLeft = '12px';
  info2.style.color = 'var(--dim)';
  info2.textContent = `Page ${curPage} / ${pages}`;
  ctrl.appendChild(info2);
}

function pageBtn(p, base, active){
  const b = document.createElement('button');
  b.textContent = p;
  b.setAttribute('style', p === curPage ? active : base);
  b.onclick = () => { curPage = p; renderPage(); };
  return b;
}
function ellipsis(){
  const s = document.createElement('span');
  s.textContent = '…';
  s.style.padding = '0 4px';
  s.style.color = 'var(--dim)';
  return s;
}

// ── Column sort ──────────────────────────────────────────────────
let _sortCol = -1;
let _sortAsc = true;

function _cellText(row, col){
  const td = row.querySelectorAll('td')[col];
  return td ? td.textContent.trim().toLowerCase() : '';
}

function sortBy(col){
  if (_sortCol === col){
    _sortAsc = !_sortAsc;
  } else {
    _sortCol = col;
    _sortAsc = true;
  }

  document.querySelectorAll('th.sortable').forEach(th => {
    th.classList.remove('sort-asc','sort-desc');
    if (parseInt(th.getAttribute('data-col')) === _sortCol){
      th.classList.add(_sortAsc ? 'sort-asc' : 'sort-desc');
    }
  });

  // Context sort order: production < test < docs < deleted_file
  const _ctxOrder = {production:0, test:1, docs:2, deleted_file:3};

  allRows.sort((a, b) => {
    if (col === 0){
      const an = parseInt(a.getAttribute('data-sev')) || 99;
      const bn = parseInt(b.getAttribute('data-sev')) || 99;
      return _sortAsc ? an - bn : bn - an;
    }
    if (col === 4){
      const ac = _ctxOrder[a.getAttribute('data-ctx')] ?? 99;
      const bc = _ctxOrder[b.getAttribute('data-ctx')] ?? 99;
      return _sortAsc ? ac - bc : bc - ac;
    }
    const av = _cellText(a, col);
    const bv = _cellText(b, col);
    return _sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  });

  const tbody = document.getElementById('ft-body');
  if (tbody) allRows.forEach(r => tbody.appendChild(r));

  curPage = 1;
  renderPage();
}

// ════════════════════════════════════════════════════════════════
// FINDING DETAIL PANEL  —  click row → expand, click again → close
// Pre-baked LLM answers embedded at report-write time in window._LLM_DETAILS
// ════════════════════════════════════════════════════════════════

function toggleDetail(evt, row) {
  // Ignore text-selection gestures
  const sel = window.getSelection();
  if (sel && sel.toString().length > 0) return;

  // Ignore clicks that originated inside the detail panel itself
  if (evt.target.closest('tr.detail-row')) return;

  const existing = row.nextElementSibling;
  if (existing && existing.classList.contains('detail-row')) {
    // Close
    existing.remove();
    row.classList.remove('row-expanded');
    return;
  }

  // Close any other open panel first
  document.querySelectorAll('tr.detail-row').forEach(r => r.remove());
  document.querySelectorAll('tr.row-expanded').forEach(r => r.classList.remove('row-expanded'));

  row.classList.add('row-expanded');

  // Build the detail row
  const colCount = row.querySelectorAll('td').length;
  const detRow = document.createElement('tr');
  detRow.className = 'detail-row';
  detRow.addEventListener('click', e => e.stopPropagation());
  const detTd = document.createElement('td');
  detTd.colSpan = colCount;

  // Look up pre-baked HTML
  const llmKey = row.getAttribute('data-llm-key') || '';
  const details = (window._LLM_DETAILS || {});
  const prebaked = details[llmKey];
  const scorecard = `<div class="scorecard">`
    + `<span class="scorechip">Detector ${_esc(row.getAttribute('data-detconf') || '0')}</span>`
    + `<span class="scorechip">Production ${_esc(row.getAttribute('data-prodrel') || '0')}</span>`
    + `<span class="scorechip">Evidence ${_esc(row.getAttribute('data-evidence') || '0')}</span>`
    + `<span class="scorechip">LLM ${_esc(row.getAttribute('data-llmconf') || '—')}</span>`
    + `<span class="scorechip">Signal ${_esc(row.getAttribute('data-signal') || '0')}</span>`
    + `</div>`;

  if (prebaked) {
    detTd.innerHTML = prebaked.replace('<div class="detail-panel">', `<div class="detail-panel">${scorecard}`);
  } else {
    // No pre-baked answer — show informational message (no live fetch)
    const model = (window.OLLAMA_MODEL || '').trim();
    const msg = model
      ? `<p style="color:#f97316;font-size:12px">⚠ LLM analysis was not generated for this finding. ` +
        `Re-run the scan with LLM enabled to embed answers in the report.</p>`
      : `<p style="color:var(--dim);font-size:12px">ℹ LLM analysis not available — no model was configured when this report was generated.</p>`;
    detTd.innerHTML = `<div class="detail-panel">${scorecard}${msg}</div>`;
  }

  detRow.appendChild(detTd);
  row.after(detRow);
}


function _esc(str) {
  return String(str || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}
</script>"""

