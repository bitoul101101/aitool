"""
Security Analyzer: evaluates raw findings against policy,
assigns final severity, risk labels, and remediation tips.
"""

from typing import List, Dict, Any


# Remediation library keyed by provider_or_lib / category
REMEDIATION_MAP = {
    "hardcoded_key": (
        "Remove hardcoded key. Use environment variables (os.getenv) or a secrets manager "
        "(Vault, AWS Secrets Manager, Azure Key Vault). Add key patterns to .gitignore and rotate the key immediately."
    ),
    "openai_key_pattern": (
        "Rotate this OpenAI key immediately. Store keys in environment variables or a secrets vault. "
        "Add 'sk-' pattern scanning to your CI pipeline pre-commit hooks."
    ),
    "anthropic_key_pattern": (
        "Rotate this Anthropic key immediately. Use environment variables; never commit keys. "
        "Enable key scoping/restriction in the Anthropic console."
    ),
    "prompt_injection_risk": (
        "Sanitize all user-controlled input before injecting into prompts. "
        "Use a prompt template library, validate input length/content, and consider an input guardrail layer."
    ),
    "logging_risk": (
        "Avoid logging raw prompts or responses. Log metadata only (token count, latency, request_id). "
        "If full logging is needed, use a dedicated PII-scrubbing pipeline and restrict log access."
    ),
    "unsafe_code_exec": (
        "Isolate any LLM-generated code execution in a sandboxed environment (container, subprocess with restricted permissions). "
        "Never exec() model outputs directly in production. Review capability policies."
    ),
    "sql_injection_risk": (
        "Use parameterized queries or ORM-level protections. Never pass LLM-generated SQL strings directly to execute(). "
        "Validate and whitelist table/column names if dynamic queries are required."
    ),
    "weak_config": (
        "Set explicit max_tokens limits appropriate to your use case. "
        "Unbounded outputs risk leaking context window content and inflating costs."
    ),
    "debug_mode": (
        "Disable debug/verbose mode in production. Debug logs may expose full prompts, responses, and internal context. "
        "Use structured logging with log levels."
    ),
    "notebook_output_secret": (
        "Clear all notebook outputs before committing (nbstripout). "
        "Rotate any exposed credentials immediately. Add nbstripout to pre-commit hooks."
    ),
    # JS/TS providers
    "openai_js": (
        "Confirm OpenAI JS/TS usage is approved. Store the API key server-side only — "
        "never bundle it into client-side code. Use environment variables and a backend proxy if needed."
    ),
    "anthropic_js": (
        "Confirm Anthropic JS/TS usage is approved. Keep the API key server-side; "
        "never expose it in browser bundles or Next.js client components."
    ),
    "google_ai_js": (
        "Confirm Google AI JS/TS usage is approved. Restrict the API key to server-side routes "
        "and apply GCP API key restrictions to limit scope."
    ),
    "vercel_ai_sdk": (
        "Verify which underlying provider the Vercel AI SDK is routing to and confirm it is approved. "
        "Ensure API keys are set as environment variables in the deployment platform."
    ),
    "langchain_js": (
        "Audit which providers and tools LangChain JS is configured with — each must be independently approved. "
        "Review tool definitions for unsafe capabilities."
    ),
    "js_hardcoded_key": (
        "Remove the hardcoded API key from source immediately, rotate it, and store it in "
        "an environment variable or secrets manager. Add a pre-commit hook to prevent recurrence."
    ),
    "nextjs_ai_route": (
        "Ensure AI API routes are protected by authentication middleware. "
        "Apply rate limiting and input validation before forwarding requests to the LLM provider."
    ),
    # Config patterns
    "env_file_key": (
        "Verify this .env file is listed in .gitignore and has never been committed. "
        "Use a secrets manager (Vault, AWS Secrets Manager) for production; .env is for local dev only."
    ),
    "docker_compose_key": (
        "Replace plaintext environment variable values in docker-compose with Docker secrets or "
        "references to a secrets manager. Never hardcode key values in compose files."
    ),
    "terraform_ai_resource": (
        "Review IAM roles and network policies attached to this AI service resource. "
        "Enable audit logging and ensure the resource is not publicly accessible."
    ),
    "k8s_model_serving": (
        "Confirm the model-serving endpoint is not exposed outside the cluster without authentication. "
        "Apply ResourceQuota and NetworkPolicy to limit blast radius."
    ),
    "dependency_declaration": (
        "Pin AI library versions to exact releases (==) and run dependency audits in CI. "
        "Confirm the library is on the approved list before merging."
    ),
    "ci_secret_ref": (
        "Limit CI secret scope to the minimum required jobs and branches. "
        "Rotate the key if the workflow has ever run on a fork PR."
    ),
    "model_name_in_config": (
        "Move model selection to an environment variable so it can be updated without a code change. "
        "Document the approved model versions in your AI policy register."
    ),
    # Agent / gateway patterns
    "litellm": (
        "Review the LiteLLM routing config — ensure it cannot fall back to unapproved providers. "
        "Enable LiteLLM's budget/rate-limit controls and audit logging."
    ),
    "portkey": (
        "Confirm Portkey is configured with a provider allowlist. "
        "Review the data retention settings on the Portkey dashboard and ensure they comply with your data policy."
    ),
    "helicone": (
        "All prompts and completions pass through Helicone's servers. "
        "Confirm this is permitted under your data classification policy and review their data retention settings."
    ),
    "autogen": (
        "Review code-execution settings on UserProxyAgent — disable or sandbox code execution in production. "
        "Implement human-in-the-loop approval for any agent action that modifies external state."
    ),
    "crewai": (
        "Audit each agent's tool list and restrict to the minimum required capabilities. "
        "Do not grant agents file-system or network tools without explicit policy approval."
    ),
    "semantic_kernel": (
        "Review registered plugins for unsafe I/O operations. "
        "Audit memory store configuration to ensure conversation history is not retained beyond session scope."
    ),
    "langgraph": (
        "Review each graph node for unsafe tool calls. "
        "Ensure the state schema does not persist PII and that graph execution is bounded with timeouts."
    ),
    "openai_assistants": (
        "Audit every registered function/tool for security implications. "
        "Ensure the model cannot trigger destructive or irreversible operations without human confirmation."
    ),
    "nocode_ai_platform": (
        "Confirm the platform is self-hosted or explicitly approved. "
        "Review data flows to ensure no sensitive data is sent to unapproved third-party services."
    ),
    "aws_bedrock": (
        "Confirm the IAM role has least-privilege Bedrock permissions. "
        "Review prompt logging configuration — ensure CloudWatch logs are access-controlled."
    ),
    "azure_ai_foundry": (
        "Verify content filters and responsible AI policies are enabled on the deployment. "
        "Confirm the Azure region meets data residency requirements."
    ),
    # Categories
    "AI Proxy/Gateway": (
        "Review the proxy/gateway configuration to ensure it cannot route to unapproved providers. "
        "Enable audit logging and apply rate limits."
    ),
    "Agent Framework": (
        "Audit all tools and plugins registered with this agent framework. "
        "Restrict capabilities to the minimum required and implement human-in-the-loop controls for high-risk actions."
    ),
    "openai": (
        "Confirm OpenAI usage is approved per AI policy. Ensure data classification allows sending to external APIs. "
        "Use Azure OpenAI if available as the approved endpoint. Document usage with policy tag."
    ),
    "anthropic": (
        "Confirm Anthropic usage is approved per AI policy. Review data sensitivity before sending to external API. "
        "Document usage and obtain approval if not already done."
    ),
    "google_gemini_vertexai": (
        "Ensure Vertex AI or Gemini usage is approved. Prefer Vertex AI (GCP-hosted) over direct Gemini API for data residency control. "
        "Review prompt content for PII/sensitive data."
    ),
    "cohere": (
        "Confirm Cohere usage is approved. Review data classification. "
        "Ensure API key rotation policy is in place."
    ),
    "huggingface_hub": (
        "Confirm HuggingFace Inference API usage is approved. Review model terms of use. "
        "Consider self-hosted HF inference for sensitive data."
    ),
    "rag_pattern": (
        "Audit RAG ingestion pipeline: ensure ingested documents are classified and authorized for AI processing. "
        "Sanitize user queries before RAG retrieval. Apply access controls on retrieved content."
    ),
    "peft_lora": (
        "Fine-tuning with internal data requires data governance review. "
        "Ensure training data is anonymized and authorized. Document model lineage."
    ),
    "trl": (
        "RLHF/fine-tuning pipelines using internal data require security and privacy review. "
        "Ensure feedback data doesn't contain PII. Document model provenance."
    ),
    "_default": (
        "Review this AI usage against the internal AI policy. "
        "Ensure the provider/library is approved, data handling is documented, and usage is logged."
    ),
}

RISK_LABELS = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low",
}


class SecurityAnalyzer:

    def __init__(self, policy: dict, verbose: bool = False):
        self.policy = policy
        self.verbose = verbose
        self.approved = set(policy.get("approved_providers", []))
        self.restricted = set(policy.get("restricted_providers", []))
        self.banned = set(policy.get("banned_providers", []))

    def analyze(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich each finding with policy status, risk, severity, and remediation."""
        enriched = []
        for f in findings:
            e = dict(f)
            e = self._apply_policy(e)
            e = self._assign_risk_label(e)
            e = self._assign_remediation(e)
            e["severity_label"] = f"Sev-{e['severity']} ({RISK_LABELS[e['severity']]})"
            enriched.append(e)
        return enriched

    def _apply_policy(self, f: Dict) -> Dict:
        lib = f.get("provider_or_lib", "")
        cat = f.get("category", "")

        # Security findings are always CRITICAL policy-wise → severity=1
        if cat == "Security":
            f["policy_status"] = "CRITICAL"
            f["severity"] = 1
            return f

        # Check against policy lists
        if lib in self.banned:
            f["policy_status"] = "BANNED"
            f["severity"] = min(f["severity"], 1)
        elif lib in self.restricted:
            f["policy_status"] = "RESTRICTED"
            f["severity"] = min(f["severity"], 2)
        elif lib in self.approved:
            f["policy_status"] = "APPROVED"
            # Approved providers get severity bumped down by 1
            f["severity"] = min(4, f["severity"] + 1)
        else:
            # Unknown/unapproved - keep as REVIEW
            if f.get("policy_status") not in ("CRITICAL", "DENIED", "ALLOWED"):
                f["policy_status"] = "REVIEW"

        return f

    def _assign_risk_label(self, f: Dict) -> Dict:
        f["risk"] = RISK_LABELS.get(f["severity"], "Low")
        return f

    def _assign_remediation(self, f: Dict) -> Dict:
        lib = f.get("provider_or_lib", "")
        # Try specific lib first, then category default
        rem = (
            REMEDIATION_MAP.get(lib)
            or REMEDIATION_MAP.get(f.get("category", ""))
            or REMEDIATION_MAP["_default"]
        )
        f["remediation"] = rem
        return f
