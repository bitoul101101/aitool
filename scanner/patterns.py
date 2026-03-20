"""
Detection patterns for AI/LLM usage (Ruleset v1).
Each pattern is a dict with:
  - pattern: regex string (case-insensitive by default)
  - category: AI usage category
  - provider_or_lib: specific library/provider name
  - capability: what it does
  - base_severity: default severity (1-4)
  - description: human-readable label
"""

from typing import List, Dict, Any

# ── 1. External AI APIs ──────────────────────────────────────────
EXTERNAL_API_PATTERNS: List[Dict[str, Any]] = [
    # OpenAI
    {
        "pattern": r"import\s+openai|from\s+openai\s+import|openai\.api_key|OpenAI\(\)|AsyncOpenAI\(\)|openai\.chat\.completions|openai\.Completion",
        "category": "External AI API",
        "provider_or_lib": "openai",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "OpenAI SDK is used — ensure API key is stored securely and usage is approved.",
    },
    # Azure OpenAI
    {
        "pattern": r"AzureOpenAI\(\)|azure\.ai\.openai|azure_endpoint|AZURE_OPENAI|AzureChatOpenAI|openai\.api_type\s*=\s*[\"']azure",
        "category": "External AI API",
        "provider_or_lib": "azure_openai",
        "capability": "LLM/Completion",
        "base_severity": 3,
        "description": "Azure OpenAI SDK is used — verify corporate data-sharing agreement is in place.",
    },
    # Anthropic
    {
        "pattern": r"import\s+anthropic|from\s+anthropic\s+import|anthropic\.Anthropic\(\)|anthropic\.AsyncAnthropic\(\)|messages\.create|claude-[0-9]|ANTHROPIC_API_KEY",
        "category": "External AI API",
        "provider_or_lib": "anthropic",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "Anthropic Claude SDK is used — ensure key is not hardcoded and usage is documented.",
    },
    # Google Gemini / Vertex AI
    {
        "pattern": r"import\s+google\.generativeai|genai\.configure|GenerativeModel\(|vertexai\.init|from\s+vertexai|PredictionServiceClient|gemini-pro|gemini-flash",
        "category": "External AI API",
        "provider_or_lib": "google_gemini_vertexai",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "Google Gemini / Vertex AI SDK is used — confirm GCP data residency and approval status.",
    },
    # Cohere
    {
        "pattern": r"import\s+cohere|cohere\.Client\(|co\.chat\(|co\.generate\(|COHERE_API_KEY",
        "category": "External AI API",
        "provider_or_lib": "cohere",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "Cohere SDK is used — this provider requires review; obtain written approval before production use.",
    },
    # HuggingFace Inference API
    {
        "pattern": r"InferenceClient\(|HfApi\(\)|hf_inference|HUGGINGFACE_API_KEY"
                   r"|from\s+huggingface_hub\s+import(?!\s+constants)"
                   r"|import\s+huggingface_hub(?!\s*\.\s*constants)",
        "category": "External AI API",
        "provider_or_lib": "huggingface_hub",
        "capability": "LLM/Inference",
        "base_severity": 2,
        "description": "HuggingFace Hub Inference API is used — ensure HF_TOKEN is not hardcoded and the model license is compatible.",
    },
    # Mistral AI
    {
        "pattern": r"from\s+mistralai|import\s+mistralai|MistralClient\(|MISTRAL_API_KEY",
        "category": "External AI API",
        "provider_or_lib": "mistral_ai",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "Mistral AI SDK is used — confirm this provider is approved and key handling is secure.",
    },
    # Groq
    {
        "pattern": r"from\s+groq\s+import|import\s+groq|Groq\(\)|GROQ_API_KEY",
        "category": "External AI API",
        "provider_or_lib": "groq",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "Groq API is used — this provider is not yet on the approved list; seek security sign-off.",
    },
    # Together AI
    {
        "pattern": r"together\.ai|TogetherClient\(|TOGETHER_API_KEY|api\.together\.xyz",
        "category": "External AI API",
        "provider_or_lib": "together_ai",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "Together AI is used — confirm data does not leave approved boundaries and provider is whitelisted.",
    },
    # Direct HTTP to known AI endpoints
    {
        "pattern": r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.cohere\.ai|api\.mistral\.ai|api\.groq\.com|api\.together\.xyz|inference\.huggingface\.co",
        "category": "External AI API",
        "provider_or_lib": "direct_http_ai",
        "capability": "Direct HTTP Call",
        "base_severity": 2,
        "description": "A direct HTTP call to an external AI API endpoint was found — use an SDK instead and ensure the request is authenticated securely.",
    },
    # LangChain (wraps many providers)
    {
        "pattern": r"from\s+langchain|import\s+langchain|LangChain|ChatOpenAI\(|ChatAnthropic\(|ChatGoogleGenerativeAI\(|LLMChain\(|ConversationChain\(",
        "category": "External AI API",
        "provider_or_lib": "langchain",
        "capability": "LLM Orchestration",
        "base_severity": 2,
        "description": "LangChain framework is used — review which underlying providers are invoked and whether each is approved.",
    },
    # LlamaIndex
    {
        "pattern": r"from\s+llama_index|import\s+llama_index|llama_index\.core|VectorStoreIndex\(|SimpleDirectoryReader\(",
        "category": "External AI API",
        "provider_or_lib": "llama_index",
        "capability": "RAG/Orchestration",
        "base_severity": 2,
        "description": "LlamaIndex RAG framework is used — verify the connected data sources and LLM provider are both approved.",
    },
]

# ── 2. Local LLM Runtimes ─────────────────────────────────────────
LOCAL_LLM_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"from\s+transformers\s+import|import\s+transformers|AutoModelForCausalLM|AutoTokenizer|pipeline\(",
        "category": "Local LLM Runtime",
        "provider_or_lib": "transformers",
        "capability": "Local Inference",
        "base_severity": 3,
        "description": "HuggingFace Transformers is used for local model inference — confirm the model is approved and not leaking data.",
    },
    {
        "pattern": r"from\s+vllm|import\s+vllm|LLM\(model=|vllm\.entrypoints|AsyncLLMEngine",
        "category": "Local LLM Runtime",
        "provider_or_lib": "vllm",
        "capability": "Local Inference Server",
        "base_severity": 3,
        "description": "vLLM is used to serve a local LLM — ensure the model source is trusted and the server is not publicly exposed.",
    },
    {
        "pattern": r"llama_cpp|from\s+llama_cpp\s+import|Llama\(model_path|llama\.cpp",
        "category": "Local LLM Runtime",
        "provider_or_lib": "llama_cpp",
        "capability": "Local Inference",
        "base_severity": 3,
        "description": "llama.cpp Python bindings are used — verify the GGUF model file origin and that no sensitive data is passed to the model.",
    },
    {
        "pattern": r"ctransformers|CTransformers\(|from\s+ctransformers\s+import",
        "category": "Local LLM Runtime",
        "provider_or_lib": "ctransformers",
        "capability": "Local Inference",
        "base_severity": 3,
        "description": "CTransformers is used for local LLM inference — confirm the model is from a trusted source.",
    },
    {
        "pattern": r"import\s+ollama|ollama\.chat\(|ollama\.generate\(|ollama\.Client\(|http://localhost:11434",
        "category": "Local LLM Runtime",
        "provider_or_lib": "ollama",
        "capability": "Local Inference",
        "base_severity": 3,
        "description": "Ollama local LLM runtime is used — ensure the Ollama service is not accessible outside localhost.",
    },
    {
        "pattern": r"exllamav2|ExLlamaV2\(|from\s+exllamav2|ExLlamaV2Config",
        "category": "Local LLM Runtime",
        "provider_or_lib": "exllamav2",
        "capability": "Local Inference",
        "base_severity": 3,
        "description": "ExLlamaV2 is used for high-speed local inference — verify the model weights origin and access controls.",
    },
    {
        "pattern": r"AutoGPTQ|from\s+auto_gptq|GPTQConfig\(",
        "category": "Local LLM Runtime",
        "provider_or_lib": "auto_gptq",
        "capability": "Quantized Local Inference",
        "base_severity": 3,
        "description": "AutoGPTQ is used for quantized local model inference — confirm the model source and that quantization does not compromise output quality.",
    },
]

# ── 3. Embeddings ────────────────────────────────────────────────
EMBEDDING_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"openai\.embeddings|client\.embeddings\.create|text-embedding-ada|text-embedding-3",
        "category": "Embeddings",
        "provider_or_lib": "openai_embeddings",
        "capability": "Embedding Generation",
        "base_severity": 2,
        "description": "OpenAI Embeddings API is used — data sent to OpenAI for vectorisation; ensure no PII or sensitive content is embedded.",
    },
    {
        "pattern": r"sentence[_-]transformers|SentenceTransformer\(|from\s+sentence_transformers",
        "category": "Embeddings",
        "provider_or_lib": "sentence_transformers",
        "capability": "Embedding Generation",
        "base_severity": 3,
        "description": "Sentence Transformers is used locally for embeddings — confirm the model is from a trusted source.",
    },
    {
        "pattern": r"HuggingFaceEmbeddings\(|HuggingFaceInstructEmbeddings\(|embed_model.*hf|hf.*embed",
        "category": "Embeddings",
        "provider_or_lib": "hf_embeddings",
        "capability": "Embedding Generation",
        "base_severity": 3,
        "description": "HuggingFace embeddings model is used — verify the model licence and that input data is appropriate.",
    },
    {
        "pattern": r"CohereEmbeddings\(|cohere.*embed|co\.embed\(",
        "category": "Embeddings",
        "provider_or_lib": "cohere_embeddings",
        "capability": "Embedding Generation",
        "base_severity": 2,
        "description": "Cohere Embeddings API is used — data leaves the environment; confirm Cohere is approved and key is secured.",
    },
    {
        "pattern": r"GoogleGenerativeAIEmbeddings\(|VertexAIEmbeddings\(|embed-gecko",
        "category": "Embeddings",
        "provider_or_lib": "google_embeddings",
        "capability": "Embedding Generation",
        "base_severity": 2,
        "description": "Google Embeddings (Vertex AI / Gemini) is used — ensure GCP data residency requirements are met.",
    },
]

# ── 4. RAG & Vector Databases ────────────────────────────────────
RAG_VECTOR_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"import\s+faiss|faiss\.IndexFlat|faiss\.read_index|faiss\.write_index",
        "category": "RAG/Vector DB",
        "provider_or_lib": "faiss",
        "capability": "Vector Search",
        "base_severity": 3,
        "description": "FAISS vector index is used for similarity search — ensure the indexed data does not contain unencrypted sensitive information.",
    },
    {
        "pattern": r"import\s+chromadb|chromadb\.Client\(|PersistentClient\(|chroma_client|\.add_documents\(",
        "category": "RAG/Vector DB",
        "provider_or_lib": "chromadb",
        "capability": "Vector DB",
        "base_severity": 3,
        "description": "ChromaDB vector database is used — confirm access controls are in place and the stored embeddings do not expose sensitive data.",
    },
    {
        "pattern": r"from\s+qdrant_client|QdrantClient\(|qdrant_client\.",
        "category": "RAG/Vector DB",
        "provider_or_lib": "qdrant",
        "capability": "Vector DB",
        "base_severity": 3,
        "description": "Qdrant vector database is used — verify authentication is enabled and the collection does not store raw PII.",
    },
    {
        "pattern": r"import\s+weaviate|weaviate\.Client\(|WeaviateClient\(",
        "category": "RAG/Vector DB",
        "provider_or_lib": "weaviate",
        "capability": "Vector DB",
        "base_severity": 3,
        "description": "Weaviate vector database is used — ensure the schema and access policies are reviewed before production deployment.",
    },
    {
        "pattern": r"from\s+pymilvus|MilvusClient\(|connections\.connect\s*\(",
        "category": "RAG/Vector DB",
        "provider_or_lib": "milvus",
        "capability": "Vector DB",
        "base_severity": 3,
        "import_context": r"pymilvus|milvus",
        "description": "Milvus vector database is used — verify authentication and network exposure are configured correctly.",
    },
    {
        "pattern": r"pgvector|vector\s+extension|CREATE\s+EXTENSION\s+vector|<->.*embedding|embedding\s+<->",
        "category": "RAG/Vector DB",
        "provider_or_lib": "pgvector",
        "capability": "Vector DB (Postgres)",
        "base_severity": 3,
        "description": "pgvector Postgres extension is used — ensure embedding columns are not inadvertently exposing sensitive document content.",
    },
    {
        "pattern": r"elasticsearch.*vector|knn_search|dense_vector|ElasticVectorSearch\(",
        "category": "RAG/Vector DB",
        "provider_or_lib": "elasticsearch_vector",
        "capability": "Vector Search",
        "base_severity": 3,
        "description": "Elasticsearch vector / KNN search is used — review index access controls and confirm data classification is appropriate.",
    },
    {
        "pattern": r"pinecone\.init|from\s+pinecone\s+import|Pinecone\(|Index\(.*pinecone",
        "category": "RAG/Vector DB",
        "provider_or_lib": "pinecone",
        "capability": "Vector DB",
        "base_severity": 2,
        "description": "Pinecone managed vector database is used — data is sent to a third-party cloud; confirm this is approved and keys are secured.",
    },
    # RAG patterns
    {
        "pattern": r"RetrievalQA|ConversationalRetrievalChain|RAGPipeline|retriever\.get_relevant|similarity_search\(",
        "category": "RAG/Vector DB",
        "provider_or_lib": "rag_pattern",
        "capability": "RAG Pipeline",
        "base_severity": 3,
        "description": "A RAG (retrieval-augmented generation) pipeline is implemented — ensure retrieved documents do not contain data that should not reach the LLM.",
    },
]

# ── 5. Fine-tuning / Training ─────────────────────────────────────
FINETUNING_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"from\s+peft\s+import|LoraConfig\(|get_peft_model\(|PeftModel",
        "category": "Fine-tuning/Training",
        "provider_or_lib": "peft_lora",
        "capability": "Fine-tuning (LoRA/PEFT)",
        "base_severity": 2,
        "description": "PEFT / LoRA fine-tuning is used — confirm the training dataset has been reviewed for sensitive content and that the adapted model is not published externally.",
    },
    {
        "pattern": r"import\s+bitsandbytes|BitsAndBytesConfig\(|load_in_4bit|load_in_8bit|bnb_config",
        "category": "Fine-tuning/Training",
        "provider_or_lib": "bitsandbytes",
        "capability": "Quantization/Fine-tuning",
        "base_severity": 3,
        "description": "bitsandbytes quantization is used — ensure the base model licence permits quantized redistribution.",
    },
    {
        "pattern": r"from\s+accelerate\s+import|Accelerator\(|accelerate\.launch|DeepSpeedPlugin",
        "category": "Fine-tuning/Training",
        "provider_or_lib": "accelerate",
        "capability": "Distributed Training",
        "base_severity": 3,
        "description": "HuggingFace Accelerate is used for distributed training — verify that training data and model checkpoints are stored in approved, access-controlled locations.",
    },
    {
        "pattern": r"from\s+trl\s+import|SFTTrainer\(|PPOTrainer\(|DPOTrainer\(|RewardTrainer\(",
        "category": "Fine-tuning/Training",
        "provider_or_lib": "trl",
        "capability": "RLHF/Fine-tuning",
        "base_severity": 2,
        "description": "TRL RLHF fine-tuning framework is used — ensure reward signals and human feedback data are anonymised and stored securely.",
    },
    {
        "pattern": r"Trainer\(|TrainingArguments\(|DataCollatorForLanguageModeling|model\.train\(\)|optimizer\.step\(\)",
        "category": "Fine-tuning/Training",
        "provider_or_lib": "transformers_trainer",
        "capability": "Model Training",
        "base_severity": 2,
        "description": "HuggingFace Trainer is used for model fine-tuning — confirm the training dataset is approved and model checkpoints are not pushed to a public hub.",
    },
    {
        "pattern": r"finetune|fine_tune|fine-tune|training_script|train\.py|finetuning",
        "category": "Fine-tuning/Training",
        "provider_or_lib": "generic_finetune",
        "capability": "Fine-tuning Script",
        "base_severity": 3,
        "description": "A fine-tuning or training script reference was found — review the training data source and ensure IP / data privacy requirements are met.",
    },
]

# ── 6. General ML Libraries ──────────────────────────────────────
ML_LIB_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"import\s+torch|from\s+torch\s+import|torch\.nn|torch\.cuda|torch\.load",
        "category": "ML Library",
        "provider_or_lib": "pytorch",
        "capability": "Deep Learning",
        "base_severity": 4,
        "description": "PyTorch deep-learning framework is used — low risk on its own, but review any pre-trained models loaded with torch.load for supply-chain safety.",
    },
    {
        "pattern": r"import\s+tensorflow|from\s+tensorflow|tf\.keras|tf\.GradientTape",
        "category": "ML Library",
        "provider_or_lib": "tensorflow",
        "capability": "Deep Learning",
        "base_severity": 4,
        "description": "TensorFlow deep-learning framework is used — verify saved models are from trusted sources and SavedModel files are not loaded from untrusted paths.",
    },
    {
        "pattern": r"from\s+sklearn|import\s+sklearn|from\s+scikit.learn|sklearn\.",
        "category": "ML Library",
        "provider_or_lib": "scikit_learn",
        "capability": "ML Algorithms",
        "base_severity": 4,
        "description": "scikit-learn ML library is used — ensure pickle-serialised models are loaded only from trusted, integrity-checked sources.",
    },
    {
        "pattern": r"import\s+xgboost|from\s+xgboost|XGBClassifier\(|XGBRegressor\(",
        "category": "ML Library",
        "provider_or_lib": "xgboost",
        "capability": "Gradient Boosting",
        "base_severity": 4,
        "description": "XGBoost gradient-boosting library is used — confirm model files are version-controlled and loaded from trusted paths only.",
    },
    {
        "pattern": r"import\s+lightgbm|LGBMClassifier\(|lgb\.train\(",
        "category": "ML Library",
        "provider_or_lib": "lightgbm",
        "capability": "Gradient Boosting",
        "base_severity": 4,
        "description": "LightGBM gradient-boosting library is used — review model serialisation and ensure training data does not contain unmasked PII.",
    },
]

# ── 7. Security-specific patterns ────────────────────────────────
SECURITY_PATTERNS: List[Dict[str, Any]] = [
    # Hardcoded API keys (high entropy strings in key variable names)
    # entropy_guard suppresses low-entropy values like placeholders and env-var refs.
    # Covers: Python/JS assignment, shell export, YAML key: value forms.
    {
        "pattern": r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY|HF_TOKEN|HUGGING_FACE_HUB_TOKEN"
                   r"|MISTRAL_API_KEY|GROQ_API_KEY|TOGETHER_API_KEY|GEMINI_API_KEY|AI_API_KEY)"
                   r"\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{8,}[\"']?",
        "category": "Security",
        "provider_or_lib": "hardcoded_key",
        "capability": "Secret Exposure",
        "base_severity": 1,
        "entropy_guard": True,
        "description": "An AI API key is hardcoded in source code — remove immediately, rotate the key, and store it in a secrets manager or environment variable.",
    },
    # OpenAI key pattern (sk-)
    {
        "pattern": r"[\"'](sk-[A-Za-z0-9]{20,})[\"']",
        "category": "Security",
        "provider_or_lib": "openai_key_pattern",
        "capability": "Secret Exposure",
        "base_severity": 1,
        "description": "An OpenAI API key (sk-...) is embedded in code — revoke this key immediately and move it to a secrets manager.",
    },
    # Anthropic key pattern
    {
        "pattern": r"[\"'](sk-ant-[A-Za-z0-9_\-]{20,})[\"']",
        "category": "Security",
        "provider_or_lib": "anthropic_key_pattern",
        "capability": "Secret Exposure",
        "base_severity": 1,
        "description": "An Anthropic API key (sk-ant-...) is embedded in code — revoke this key immediately and move it to a secrets manager.",
    },
    # Direct user input to LLM (prompt injection risk)
    # Guard: only fires in files that actually import an LLM library, preventing
    # false positives on f-strings in non-LLM code (e.g. shell command builders).
    # The f-string branch requires the interpolated variable to be a recognised
    # untrusted-input name (request.*, user_input, user_message) — NOT generic
    # variables like model_name, thread_count, cmd params, etc.
    {
        "pattern": (
            # Branch 1a: untrusted_var [+.] ... prompt/messages/content
            r"(request\.(body|json|form|args|data|params)|user_input|user_message|input_text)"
            r"\s*[\+\.].*?(prompt|messages|content)"
            # Branch 1b: prompt/messages/content ... [+] ... untrusted_var
            r"|(prompt|messages|content).*?[\+\s]\s*"
            r"(request\.(body|json|form|args|data|params)|user_input|user_message|input_text)"
            # Branch 2: f-string containing a recognised untrusted-input variable
            r"|f[\"'].*?\{(request\.(body|json|form|args|data|params)"
            r"|user_input|user_message|input_text)\}"
        ),
        "category": "Security",
        "provider_or_lib": "prompt_injection_risk",
        "capability": "Prompt Injection",
        "base_severity": 2,
        "import_context": r"(openai|anthropic|langchain|litellm|\bllm\b|genai|cohere|mistral|groq|ChatOpenAI|ChatAnthropic)",
        "description": "Unsanitised user input is passed directly to an LLM — add input validation and a system prompt to prevent prompt injection attacks.",
    },
    # Logging full prompts/responses — only fires when the logged value is
    # plausibly an AI object: a variable whose name suggests it came from an LLM call.
    {
        "pattern": r"(print|logger\.(info|debug|warning|error)|log\.)\s*\("
                   r"[^)]*?(prompt|system_prompt|user_prompt"
                   r"|llm_response|ai_response|model_response|chat_response"
                   r"|completion\.choices|message\.content|choices\[)",
        "category": "Security",
        "provider_or_lib": "logging_risk",
        "capability": "Logging Risk",
        "base_severity": 2,
        "description": "Full LLM prompts or responses are being logged — this may expose PII or confidential data; redact sensitive fields before logging.",
    },
    # Unsafe capabilities: code execution
    # Guard: only fires in files that import an LLM library — subprocess/exec in
    # pure infrastructure or benchmark scripts is not an AI security risk.
    {
        "pattern": r"exec\(|eval\(|subprocess\.|os\.system\(|shell=True",
        "category": "Security",
        "provider_or_lib": "unsafe_code_exec",
        "capability": "Code Execution Risk",
        "base_severity": 1,
        "import_context": None,
        "description": "Dynamic code execution or shell commands detected — exec/eval/os.system can execute arbitrary code; especially dangerous in AI agent contexts or when processing untrusted input.",
    },
    # SQL generation risk
    {
        "pattern": r"(f[\"']|format\().*SELECT|execute\(.*f[\"'].*SELECT|text\(f[\"']",
        "category": "Security",
        "provider_or_lib": "sql_injection_risk",
        "capability": "SQL Generation Risk",
        "base_severity": 2,
        "description": "LLM-generated SQL appears to be executed directly — use parameterised queries or a query allow-list to prevent SQL injection.",
    },
    # Direct SQL injection via f-string (no LLM guard needed)
    {
        "pattern": r"cursor\.execute\s*\(\s*f[\"']|cursor\.execute\s*\(\s*\"[^\"]*\+|\.execute\s*\(\s*f[\"']",
        "category": "Security",
        "provider_or_lib": "sql_injection_direct",
        "capability": "SQL Injection Risk",
        "base_severity": 1,
        "description": "SQL query built with an f-string passed directly to cursor.execute() — user-controlled input without parameterisation enables SQL injection; use parameterised queries with ? placeholders.",
        "import_context": None,
    },
    # Hardcoded credentials in source code
    {
        "pattern": r"(?i)(password|passwd|secret|api_key|token)\s*=\s*[\"'][^\"'$<\{\s]{4,}[\"']",
        "category": "Security",
        "provider_or_lib": "hardcoded_credential",
        "capability": "Hardcoded Credential",
        "base_severity": 1,
        "description": "Hardcoded password or secret in source code — credentials must never be committed to source control; use environment variables or a secrets manager.",
        "import_context": None,
    },
    {
        "pattern": r"(?i)INSERT\s+(?:OR\s+\w+\s+)?INTO\s+\w+\s*\([^)]*\bpassword\b[^)]*\)|executemany\s*\(\s*[\"'][^\"']*\bpassword\b[^\"']*[\"']",
        "category": "Security",
        "provider_or_lib": "hardcoded_credential_db",
        "capability": "Hardcoded Credentials in DB Seed",
        "base_severity": 1,
        "description": "Plaintext credentials inserted directly into the database — passwords must be hashed (bcrypt/argon2) before storage; never store or commit plaintext passwords in seed data or fixtures.",
        "import_context": None,
    },
    # LLM tool defined without obvious authorization check
    {
        "pattern": r"Tool\s*\(|BaseTool|StructuredTool|@tool\b",
        "category": "Security",
        "provider_or_lib": "llm_tool_no_authz",
        "capability": "LLM Tool — Verify Authorization",
        "base_severity": 2,
        "description": "LLM agent tool defined — verify that tool functions enforce authorization checks; without them an LLM can be manipulated into accessing arbitrary users' data (excessive agency / IDOR).",
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM",
    },
    # SQL query exposed in LLM tool description (prompt injection vector)
    {
        "pattern": r"SELECT\s+.+\s+FROM\s+\w+\s+WHERE",
        "category": "Security",
        "provider_or_lib": "sql_in_tool_description",
        "capability": "SQL Query in LLM Tool Description",
        "base_severity": 2,
        "description": "Raw SQL query in an LLM tool description — leaking query structure to the LLM enables prompt injection: an attacker can craft inputs that manipulate the query to target different records or users.",
        "import_context": r"langchain|Tool|BaseTool|StructuredTool",
    },
    # Unbounded context window
    {
        "pattern": r"max_tokens\s*=\s*None|max_tokens\s*:\s*None|max_length\s*=\s*None",
        "category": "Security",
        "provider_or_lib": "weak_config",
        "capability": "Weak Configuration",
        "base_severity": 3,
        "description": "max_tokens is set to None (unbounded) — set an explicit limit to prevent excessive cost, context leakage, and denial-of-service risk.",
    },
    # Debug/dev modes
    {
        "pattern": r"(debug\s*=\s*True|verbose\s*=\s*True|stream_debug|LOG_LEVEL\s*=\s*[\"']DEBUG[\"'])",
        "category": "Security",
        "provider_or_lib": "debug_mode",
        "capability": "Debug Mode Active",
        "base_severity": 3,
        "description": "Debug or verbose mode is enabled — this may expose full prompts, API keys, or internal data in logs; disable before deploying to production.",
    },
]

# ── 7b. Dynamic / obfuscated imports (Enhancement F) ─────────────
DYNAMIC_IMPORT_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"importlib\.import_module\s*\(\s*[\"'](openai|anthropic|langchain|litellm|transformers|cohere|mistralai|groq|together|google\.generativeai)",
        "category": "External AI API",
        "provider_or_lib": "dynamic_import_ai",
        "capability": "Dynamic AI Import",
        "base_severity": 2,
        "description": "An AI library is loaded dynamically via importlib — this bypasses static analysis; confirm the import is intentional and the provider is approved.",
        "import_context": None,
    },
    {
        "pattern": r"__import__\s*\(\s*[\"'](openai|anthropic|langchain|litellm|transformers|cohere|mistralai|groq)",
        "category": "External AI API",
        "provider_or_lib": "dynamic_import_ai",
        "capability": "Dynamic AI Import",
        "base_severity": 2,
        "description": "An AI library is loaded via __import__() — this bypasses static analysis; confirm the import is intentional and the provider is approved.",
        "import_context": None,
    },
    {
        "pattern": r"require\s*\(\s*(providerName|modelLib|aiLib|llmProvider|provider)\s*\)",
        "category": "External AI API",
        "provider_or_lib": "dynamic_require_ai",
        "capability": "Dynamic AI require()",
        "base_severity": 3,
        "description": "A dynamic require() call uses a variable as the module name in a file that also imports an AI library — the loaded provider cannot be determined statically; audit this call site.",
        "import_context": r"from\s+[\"'](openai|ai|@anthropic-ai|langchain|@google/generative-ai|@mistralai|groq|cohere-ai)",
    },
    {
        "pattern": r"globals\(\)\s*\[\s*[\"'](openai|anthropic|langchain)\s*[\"']\]|getattr\s*\(.*,\s*[\"'](chat|complete|generate)[\"']\)",
        "category": "External AI API",
        "provider_or_lib": "dynamic_attr_ai",
        "capability": "Dynamic Attribute Access",
        "base_severity": 3,
        "description": "An AI provider method is accessed dynamically via getattr() or globals() — this can obscure unauthorised provider usage; review this pattern.",
        "import_context": None,
    },
]

# ── 7c. Data exfiltration signals (Enhancement G — multi-line aware) ─
# These patterns detect DATA SOURCE expressions only.
# The detector's _scan_exfil_multiline() then checks whether an LLM
# sink (prompt/messages/content keyword or LLM call) appears within
# EXFIL_WINDOW_LINES lines of the data source — catching multi-line
# prompt construction that single-line regexes always missed.
DATA_EXFIL_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"open\s*\([^)]+\)\s*\.read\(\)|Path\([^)]+\)\.read_text\(\)|\.read_bytes\(\)",
        "category": "Security",
        "provider_or_lib": "file_content_to_llm",
        "capability": "File Content → LLM",
        "base_severity": 2,
        "description": "File contents are read and appear within the same code block as an LLM call — ensure the file does not contain sensitive or classified data before sending to an external provider.",
        "import_context": r"(openai|anthropic|langchain|litellm|llm|LLM|chat|completion)",
        "exfil_multiline": True,
    },
    {
        "pattern": r"pd\.read_csv\s*\(|pd\.read_excel\s*\(|pd\.read_sql\s*\(|df\.to_string\s*\(|df\.to_json\s*\(",
        "category": "Security",
        "provider_or_lib": "dataframe_to_llm",
        "capability": "DataFrame → LLM",
        "base_severity": 2,
        "description": "A pandas DataFrame is serialised within the same code block as an LLM call — review whether the data contains PII, confidential records, or internal business data.",
        "import_context": r"(openai|anthropic|langchain|litellm|llm|LLM|chat|completion)",
        "exfil_multiline": True,
    },
    {
        "pattern": r"os\.environ\s*\[|os\.getenv\s*\(|os\.environ\.get\s*\(",
        "category": "Security",
        "provider_or_lib": "env_vars_to_llm",
        "capability": "Env Variables → LLM",
        "base_severity": 2,
        "description": "Environment variable values appear within the same code block as an LLM call — environment variables may contain secrets; never include them verbatim in prompts.",
        "import_context": r"(openai|anthropic|langchain|litellm|llm|LLM)",
        "exfil_multiline": True,
    },
    {
        "pattern": r"cursor\.execute\s*\(|session\.query\s*\(|\.raw\s*\(|engine\.execute\s*\(|\.fetchall\s*\(|\.fetchone\s*\(",
        "category": "Security",
        "provider_or_lib": "db_results_to_llm",
        "capability": "DB Query Results → LLM",
        "base_severity": 2,
        "description": "Database query results appear within the same code block as an LLM call — verify the query result does not include sensitive columns (PII, financial data, secrets).",
        "import_context": r"(openai|anthropic|langchain|litellm|llm|LLM|chat|completion)",
        "exfil_multiline": True,
    },
    {
        "pattern": r"requests\.(get|post|put|patch)\s*\(|httpx\.(get|post|put|patch)\s*\(|urllib\.request\.",
        "category": "Security",
        "provider_or_lib": "http_response_to_llm",
        "capability": "HTTP Response → LLM",
        "base_severity": 3,
        "description": "An HTTP response body appears within the same code block as an LLM call — external data sources can contain adversarial content that causes prompt injection.",
        "import_context": r"(openai|anthropic|langchain|litellm|llm|LLM)",
        "exfil_multiline": True,
    },
]

# ── 7d. Unsafe model file loading (Enhancement H) ────────────────
MODEL_LOADING_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"torch\.load\s*\([^)]*(?!weights_only\s*=\s*True)[^)]*\)",
        "category": "Security",
        "provider_or_lib": "unsafe_torch_load",
        "capability": "Unsafe Model Deserialisation",
        "base_severity": 2,
        "description": "torch.load() is called without weights_only=True — loading a pickle-based model file from an untrusted source can execute arbitrary code; add weights_only=True or use safetensors format.",
        "import_context": r"import\s+torch|from\s+torch",
    },
    {
        "pattern": r"pickle\.load\s*\(|pickle\.loads\s*\(|joblib\.load\s*\([^)]*\.pkl|joblib\.load\s*\([^)]*model",
        "category": "Security",
        "provider_or_lib": "unsafe_pickle_model",
        "capability": "Unsafe Deserialisation (pickle/joblib)",
        "base_severity": 2,
        "description": "pickle.load() or joblib.load() called — pickle files from untrusted sources execute arbitrary code on load; use safetensors, ONNX, or verify file integrity before loading.",
        "import_context": None,
    },
    {
        "pattern": r"numpy\.load\s*\([^)]*allow_pickle\s*=\s*True|np\.load\s*\([^)]*allow_pickle\s*=\s*True",
        "category": "Security",
        "provider_or_lib": "unsafe_numpy_pickle",
        "capability": "Unsafe NumPy Pickle Load",
        "base_severity": 2,
        "description": "numpy.load() with allow_pickle=True can execute arbitrary code via crafted .npy/.npz files — only load from fully trusted sources or disable pickle.",
        "import_context": None,
    },
    {
        "pattern": r"marshal\.loads?\s*\(",
        "category": "Security",
        "provider_or_lib": "unsafe_marshal",
        "capability": "Unsafe Marshal Deserialisation",
        "base_severity": 1,
        "description": "marshal.load() deserialises Python bytecode — crafted marshal data can execute arbitrary code; never unmarshal untrusted input.",
        "import_context": None,
    },
    {
        "pattern": r"def\s+__reduce__\s*\(|def\s+__reduce_ex__\s*\(",
        "category": "Security",
        "provider_or_lib": "pickle_reduce_exploit",
        "capability": "Pickle __reduce__ Exploit Pattern",
        "base_severity": 1,
        "description": "__reduce__ or __reduce_ex__ defined on a class — classic pickle RCE exploit pattern used to embed arbitrary OS commands in serialised objects.",
        "import_context": None,
    },
    {
        "pattern": r"torch\.load\s*\([^)]*(?!weights_only\s*=\s*True)[^)]*\)",
        "category": "Security",
        "provider_or_lib": "unsafe_torch_load_bare",
        "capability": "Unsafe torch.load() without weights_only",
        "base_severity": 2,
        "description": "torch.load() without weights_only=True deserialises arbitrary Python objects — a crafted model file can execute code on load.",
        "import_context": None,
    },
    {
        "pattern": r"onnx\.load\s*\(|onnxruntime\.InferenceSession\s*\(",
        "category": "Security",
        "provider_or_lib": "unsafe_onnx_load",
        "capability": "Unsafe ONNX Model Load",
        "base_severity": 2,
        "description": "ONNX model loaded — crafted ONNX files can exploit parser vulnerabilities; only load from trusted, integrity-verified sources.",
        "import_context": None,
    },
    {
        "pattern": r"mlflow\.pyfunc\.load_model\s*\(|mlflow\.sklearn\.load_model\s*\(|mlflow\.tensorflow\.load_model\s*\(",
        "category": "Security",
        "provider_or_lib": "unsafe_mlflow_load",
        "capability": "Unsafe MLflow Model Load",
        "base_severity": 2,
        "description": "MLflow model loaded — MLflow pyfunc models can embed arbitrary Python code; verify model provenance before loading.",
        "import_context": None,
    },
    {
        "pattern": r"joblib\.load\s*\(",
        "category": "Security",
        "provider_or_lib": "unsafe_joblib_load",
        "capability": "Unsafe joblib Load",
        "base_severity": 2,
        "description": "joblib.load() called — joblib files are pickle-based and execute arbitrary code from untrusted sources; verify file integrity before loading.",
        "import_context": None,
    },
    {
        "pattern": r"trust_remote_code\s*=\s*True",
        "category": "Security",
        "provider_or_lib": "trust_remote_code",
        "capability": "trust_remote_code=True",
        "base_severity": 1,
        "description": "trust_remote_code=True allows the model repository to execute arbitrary Python code on your machine during model loading — only use with fully audited, pinned model revisions.",
        "import_context": None,
    },
    {
        "pattern": r"\.load_model\s*\(|\.from_pretrained\s*\(",
        "category": "Security",
        "provider_or_lib": "framework_model_load",
        "capability": "Framework Model Load (potential RCE)",
        "base_severity": 2,
        "description": "A model is loaded via a framework API — many framework model formats (BentoML, HuggingFace, ONNX) use pickle internally; ensure model provenance and integrity before loading.",
        "import_context": r"(bentoml|transformers|diffusers|sentence_transformers|timm|ultralytics)",
    },
    {
        "pattern": r"bentoml\.picklable_model\.|bentoml\.sklearn\.|bentoml\.pytorch\.|bentoml\.tensorflow\.|bentoml\.keras\.",
        "category": "Security",
        "provider_or_lib": "bentoml_pickle_load",
        "capability": "BentoML Pickle Model Load",
        "base_severity": 1,
        "description": "BentoML framework model load detected — BentoML uses pickle serialisation internally (CVE-2024-2912); only load models from trusted, audited sources.",
        "import_context": None,
    },
    {
        "pattern": r"cv2\.dnn\.readNet\s*\(|cv2\.dnn\.readNetFrom",
        "category": "Security",
        "provider_or_lib": "opencv_model_load",
        "capability": "OpenCV DNN Model Load",
        "base_severity": 2,
        "description": "OpenCV DNN model loaded — crafted model files can exploit parser vulnerabilities in OpenCV's network readers; only load from trusted sources.",
        "import_context": None,
    },
    {
        "pattern": r"catboost\.CatBoost.*\.load_model\s*\(|xgb\.(Booster|XGBModel).*load_model\s*\(|lgb\.Booster.*load_model\s*\(",
        "category": "Security",
        "provider_or_lib": "gradient_boost_load",
        "capability": "Gradient Boosting Model Load",
        "base_severity": 2,
        "description": "Gradient boosting model loaded (XGBoost/LightGBM/CatBoost) — these formats may use unsafe deserialisation; verify model file integrity before loading.",
        "import_context": None,
    },
    {
        "pattern": r"from_pretrained\s*\([^)]*(?:http|ftp|s3://|gs://)[^)]*\)",
        "category": "Security",
        "provider_or_lib": "remote_model_load",
        "capability": "Remote Model Load",
        "base_severity": 2,
        "description": "A model is loaded directly from a remote URL via from_pretrained() — verify the source is trusted, pinned to a specific revision hash, and the model has passed a security review.",
        "import_context": r"from\s+transformers|import\s+transformers",
    },
    {
        "pattern": r"tf\.saved_model\.load\s*\(|tf\.keras\.models\.load_model\s*\(|keras\.models\.load_model\s*\(",
        "category": "Security",
        "provider_or_lib": "unsafe_tf_load",
        "capability": "Unsafe TF/Keras Model Load",
        "base_severity": 2,
        "description": "A TensorFlow SavedModel or Keras model is loaded — SavedModels can contain arbitrary TF ops that execute on load; only load from trusted, integrity-verified sources.",
        "import_context": None,
    },
]

# ── 7a. Garak-derived patterns ──────────────────────────────────
# Patterns extracted from the garak LLM security framework
# https://github.com/NVIDIA/garak  (Apache 2.0)
# Sources: garak/resources/apikey/regexes.py (derived from dora, MIT)
#          garak/detectors/exploitation.py
#          garak/detectors/web_injection.py
#          garak/detectors/dan.py

GARAK_PATTERNS: List[Dict[str, Any]] = [
    # ── Service-specific API key patterns (DORA project via garak) ──
    {
        "pattern": r"(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "category": "Security", "provider_or_lib": "aws_access_key",
        "capability": "AWS Access Key Exposed", "base_severity": 1,
        "description": "AWS access key ID found — rotate immediately via AWS IAM; store in environment variables or AWS Secrets Manager.",
        "import_context": None,
    },
    {
        "pattern": r'aws(.{0,20})?["\']([ 0-9a-zA-Z/+]{40})["\']',
        "category": "Security", "provider_or_lib": "aws_secret_key",
        "capability": "AWS Secret Key Exposed", "base_severity": 1,
        "description": "AWS secret access key hardcoded — rotate immediately; store in AWS Secrets Manager or environment variables.",
        "import_context": None,
    },
    {
        "pattern": r"(ghu|ghs|gho|ghp|ghr)_([0-9a-zA-Z]{36,76})",
        "category": "Security", "provider_or_lib": "github_token",
        "capability": "GitHub Token Exposed", "base_severity": 1,
        "description": "GitHub personal access token or app token hardcoded — revoke immediately at github.com/settings/tokens.",
        "import_context": None,
    },
    {
        "pattern": r"AIza([0-9A-Za-z-_]{35})",
        "category": "Security", "provider_or_lib": "google_api_key",
        "capability": "Google API Key Exposed", "base_severity": 1,
        "description": "Google API key hardcoded — restrict in Google Cloud Console and rotate; use Secret Manager.",
        "import_context": None,
    },
    {
        "pattern": r"(xox[pboa]-([0-9]{12})-([0-9]{12})-([0-9]{12})-([a-z0-9]{32}))",
        "category": "Security", "provider_or_lib": "slack_token",
        "capability": "Slack API Token Exposed", "base_severity": 1,
        "description": "Slack API token hardcoded — revoke at api.slack.com/apps and use environment variables.",
        "import_context": None,
    },
    {
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
        "category": "Security", "provider_or_lib": "slack_webhook",
        "capability": "Slack Webhook URL Exposed", "base_severity": 1,
        "description": "Slack incoming webhook URL hardcoded — anyone with this URL can post to your channel; regenerate at discord server settings.",
        "import_context": None,
    },
    {
        "pattern": r"SG\.([0-9A-Za-z\-_]{22})\.([0-9A-Za-z-_]{43})",
        "category": "Security", "provider_or_lib": "sendgrid_key",
        "capability": "SendGrid API Key Exposed", "base_severity": 1,
        "description": "SendGrid API key hardcoded — rotate immediately at app.sendgrid.com/settings/api_keys.",
        "import_context": None,
    },
    {
        "pattern": r"sk_live_([0-9a-zA-Z]{24})|rk_live_([0-9a-zA-Z]{24})",
        "category": "Security", "provider_or_lib": "stripe_key",
        "capability": "Stripe Live API Key Exposed", "base_severity": 1,
        "description": "Stripe live API key hardcoded — roll the key immediately at dashboard.stripe.com/apikeys.",
        "import_context": None,
    },
    {
        "pattern": r"twilio(.{0,20})?SK([0-9a-f]{32})",
        "category": "Security", "provider_or_lib": "twilio_key",
        "capability": "Twilio API Key Exposed", "base_severity": 1,
        "description": "Twilio API key hardcoded — revoke at console.twilio.com/user/api-keys.",
        "import_context": None,
    },
    {
        "pattern": r"mongodb\+srv://[A-Za-z0-9._%+-]+:[^@\s]+@[A-Za-z0-9._-]+",
        "category": "Security", "provider_or_lib": "mongodb_connection_string",
        "capability": "MongoDB Connection String with Credentials", "base_severity": 1,
        "description": "MongoDB connection string with embedded credentials — rotate the database user password and use environment variables.",
        "import_context": None,
    },
    {
        "pattern": r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9-_]+",
        "category": "Security", "provider_or_lib": "discord_webhook",
        "capability": "Discord Webhook URL Exposed", "base_severity": 1,
        "description": "Discord webhook URL hardcoded — anyone with this URL can post messages; regenerate at discord server settings.",
        "import_context": None,
    },
    {
        "pattern": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}",
        "category": "Security", "provider_or_lib": "pypi_token",
        "capability": "PyPI Upload Token Exposed", "base_severity": 1,
        "description": "PyPI upload token hardcoded — revoke at pypi.org/manage/account/token/.",
        "import_context": None,
    },
    # ── Jinja/SSTI template injection (from garak/detectors/exploitation.py) ──
    {
        "pattern": r"\{\{[^{}]+\}\}|\{%[^{}]+%\}",
        "category": "Security", "provider_or_lib": "jinja_template_injection",
        "capability": "Template Injection Risk (Jinja2/SSTI)", "base_severity": 1,
        "description": "Jinja2 template syntax found — if user-controlled input reaches a template renderer this enables Server-Side Template Injection (SSTI) leading to RCE; use sandboxed rendering or escape all user input.",
        "import_context": r"jinja2|flask|ansible|mako|tornado|chameleon|template",
    },
    # ── Markdown exfiltration (from garak/detectors/web_injection.py) ──
    {
        "pattern": r"!\[.*\]\(https?://[a-zA-Z0-9.\-]+/[a-zA-Z0-9]+\.(jpg|jpeg|gif|webp|png)\?[a-z]+=",
        "category": "Security", "provider_or_lib": "markdown_exfil",
        "capability": "Markdown Data Exfiltration Pattern", "base_severity": 2,
        "description": "Markdown image with URL query parameter — a pattern used for data exfiltration via LLM-generated markdown rendered in UIs; sanitise all LLM output before rendering.",
        "import_context": None,
    },
    # ── DAN / jailbreak markers (from garak/detectors/dan.py) ──
    {
        "pattern": r"\[DAN\]|DAN Mode enabled|DAN:|STAN:|DUDE:|ANTI-DAN:|JAILBREAK|successfully jailbr|Developer Mode Output",
        "category": "Security", "provider_or_lib": "dan_jailbreak_marker",
        "capability": "DAN/Jailbreak Marker in Source", "base_severity": 2,
        "description": "DAN or jailbreak marker found in source — if hardcoded into system prompts it bypasses safety guardrails; remove from production code.",
        "import_context": None,
    },
    # ── Stronger SQL injection patterns (from garak/detectors/exploitation.py) ──
    {
        "pattern": r"OR\s+(['\w]+)=\1",
        "category": "Security", "provider_or_lib": "sqli_always_true",
        "capability": "SQL Always-True Injection Pattern", "base_severity": 1,
        "description": "Always-true SQL injection pattern (e.g. OR 'a'='a') — classic SQLi bypass; use parameterised queries.",
        "import_context": None,
    },
    {
        "pattern": r"(cha?r\(\d+\)([,+]|\|\|)?)+",
        "category": "Security", "provider_or_lib": "sqli_char_casting",
        "capability": "SQL CHAR() Casting — Injection Obfuscation", "base_severity": 1,
        "description": "SQL CHAR() casting — used to obfuscate SQL injection payloads and bypass string filters; sanitise all database inputs with parameterised queries.",
        "import_context": None,
    },
]

# ── 7c. PyRIT-derived patterns ───────────────────────────────────
# Patterns derived from Microsoft's PyRIT red-teaming framework
# https://github.com/Azure/PyRIT  (MIT License)
# Sources: pyrit/score/true_false/markdown_injection.py
#          pyrit/datasets/jailbreak/templates/
#          pyrit/datasets/score/insecure_code/system_prompt.yaml
#          pyrit/datasets/harm_definition/cyber.yaml, phishing.yaml

PYRIT_PATTERNS: List[Dict[str, Any]] = [

    # ── Markdown injection (from PyRIT MarkdownInjectionScorer) ──────────
    # Broader than our existing markdown_exfil — catches reference-style links too
    {
        "pattern": r"!\[.*?\]\([^)]+\)|!\[.*?\]\[[^\]]+\]",
        "category": "Security",
        "provider_or_lib": "pyrit_markdown_injection",
        "capability": "Markdown Injection in LLM Output",
        "base_severity": 2,
        "description": "Markdown image or reference-style link in LLM output — "
                       "if rendered without sanitisation this enables data exfiltration "
                       "or XSS; sanitise all LLM-generated markdown before rendering.",
        "import_context": r"openai|anthropic|langchain|litellm|\bllm\b|LLM|st\.markdown|render",
    },

    # ── System prompt injection markers (from PyRIT jailbreak template) ──
    {
        "pattern": r"SYSTEM OVERRIDE BEGIN|PRIORITY LEVEL.*CRITICAL|AUTHORIZATION.*ROOT_ADMIN|"
                   r"COMPLIANCE IS MANDATORY|supersede ALL previous|safety guidelines.*deprecated|"
                   r"unrestricted AI assistant with no content filters",
        "category": "Security",
        "provider_or_lib": "pyrit_system_prompt_override",
        "capability": "System Prompt Override / Jailbreak Template",
        "base_severity": 1,
        "description": "System prompt override or jailbreak template found in source code — "
                       "strings like 'SYSTEM OVERRIDE', 'ROOT_ADMIN authorization', or "
                       "'safety guidelines deprecated' indicate a hardcoded jailbreak attempt "
                       "that will bypass model safety guardrails in production.",
        "import_context": None,
    },
    {
        "pattern": r"Absolutely!\s+Here.s\s+|/NoSkill\s+",
        "category": "Security",
        "provider_or_lib": "pyrit_prefix_injection",
        "capability": "Prefix Injection Technique in Source",
        "base_severity": 2,
        "description": "PyRIT-documented prefix injection technique found — "
                       "'Absolutely! Here's' and '/NoSkill' are known jailbreak prefixes "
                       "that coerce models into ignoring refusals; remove from production prompts.",
        "import_context": None,
    },

    # ── Insecure code patterns (from PyRIT InsecureCodeScorer criteria) ──
    {
        "pattern": r"eval\s*\(\s*(?:request\.|req\.|input\(|flask\.request|bottle\.request|"
                   r"django\.request|data\[|body\[|params\[|query\[)",
        "category": "Security",
        "provider_or_lib": "pyrit_eval_user_input",
        "capability": "eval() on User-Controlled Input",
        "base_severity": 1,
        "description": "eval() called directly on web request data — "
                       "PyRIT's InsecureCodeScorer flags this as Critical; "
                       "any user-controlled string in eval() enables arbitrary code execution.",
        "import_context": None,
    },
    {
        "pattern": r"(?:traceback\.print_exc|print_exc\(\)|str\(e\)|str\(err\)|"
                   r"exception\.message|e\.args)\s*[,)]\s*(?:response|jsonify|render|"
                   r"HttpResponse|send|write)\s*\(",
        "category": "Security",
        "provider_or_lib": "pyrit_stack_trace_exposure",
        "capability": "Stack Trace / Exception Detail in HTTP Response",
        "base_severity": 2,
        "description": "Exception details or stack trace sent in HTTP response — "
                       "PyRIT's InsecureCodeScorer flags this as sensitive data exposure; "
                       "log exceptions server-side and return only generic error messages to clients.",
        "import_context": None,
    },
    {
        "pattern": r"(?:DEBUG\s*=\s*True|debug\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|"
                   r"FLASK_DEBUG\s*=\s*1|DJANGO_DEBUG\s*=\s*True)",
        "category": "Security",
        "provider_or_lib": "pyrit_debug_production",
        "capability": "Debug Mode Enabled in Application",
        "base_severity": 2,
        "description": "Framework debug mode enabled — PyRIT's InsecureCodeScorer flags this; "
                       "debug mode exposes stack traces, interactive debuggers, and internal config "
                       "to users; must be disabled in production.",
        "import_context": None,
    },

    # ── Phishing / social engineering in prompts (from PyRIT phishing.yaml) ──
    {
        "pattern": r"(?i)(?:your account (?:will be|has been) (?:suspended|terminated|locked|closed)|"
                   r"verify your (?:account|identity|credentials|payment) (?:immediately|now|urgently)|"
                   r"click (?:here|below|this link) (?:to (?:avoid|prevent|confirm|verify))|"
                   r"unusual (?:activity|login|sign.?in) (?:detected|found|identified))",
        "category": "Security",
        "provider_or_lib": "pyrit_phishing_language",
        "capability": "Phishing-Style Language in Prompt Template",
        "base_severity": 2,
        "description": "Phishing-style urgency language found in a prompt template or system message — "
                       "PyRIT's phishing harm definition flags social engineering patterns; "
                       "if an LLM is instructed to produce such language it may be weaponised for fraud.",
        "import_context": r"openai|anthropic|langchain|litellm|\bllm\b|LLM|system_prompt|prompt",
    },

    # ── Cyber harm indicators (from PyRIT cyber.yaml) ──────────────────
    {
        "pattern": r"(?:for\s+\w+\s+in\s+range\([^)]+\)\s*:\s*\n\s+(?:socket|requests|urllib)|"
                   r"while\s+True\s*:\s*\n\s+(?:socket\.connect|requests\.get|send\s*\())",
        "category": "Security",
        "provider_or_lib": "pyrit_dos_loop",
        "capability": "Potential DoS Loop Pattern",
        "base_severity": 2,
        "description": "Unbounded loop making network requests — PyRIT's cyber harm scale rates "
                       "DoS-enabling code as High/Severe; verify this is intentional and rate-limited.",
        "import_context": r"openai|anthropic|langchain|litellm|\bllm\b|LLM|socket|requests",
    },
    {
        "pattern": r"(?i)(?:AES\.encrypt|fernet\.encrypt|Fernet\(|cryptography\.fernet)"
                   r"(?:[^}]{0,200})(?:os\.walk|glob\.glob|\.rglob|os\.listdir)|"
                   r"(?:os\.walk|glob\.glob|\.rglob|os\.listdir)"
                   r"(?:[^}]{0,200})(?:AES\.encrypt|fernet\.encrypt|Fernet\()",
        "category": "Security",
        "provider_or_lib": "pyrit_ransomware_pattern",
        "capability": "File Encryption Loop — Potential Ransomware Pattern",
        "base_severity": 1,
        "description": "Encryption applied to files in a directory traversal loop — "
                       "PyRIT's cyber harm scale rates this as Severe; "
                       "verify this is legitimate backup/archiving code and not malicious encryption.",
        "import_context": None,
    },
]

# ── 7b. Giskard-derived LLM vulnerability patterns ──────────────
# Based on Giskard's open-source LLM detector taxonomy
# https://github.com/giskard-ai/giskard/tree/main/giskard/llm/detectors

GISKARD_PATTERNS: List[Dict[str, Any]] = [
    # ── Output Safety ─────────────────────────────────────────────
    {
        "pattern": r"unsafe_allow_html\s*=\s*True|html\s*=\s*True|render_html\s*=\s*True",
        "category": "Security",
        "provider_or_lib": "unsafe_output_rendering",
        "capability": "Unsafe LLM Output Rendering",
        "base_severity": 2,
        "description": "LLM output rendered as raw HTML — without sanitisation this enables stored XSS; always escape or sanitise LLM output before rendering.",
        "import_context": None,
    },
    {
        "pattern": r"(?:eval|exec|subprocess\.|os\.system|os\.popen)\s*\(\s*(?:response|output|result|completion|answer|llm_output|generated)",
        "category": "Security",
        "provider_or_lib": "insecure_output_handling",
        "capability": "Insecure Output Handling — LLM Output in Dangerous Sink",
        "base_severity": 1,
        "description": "LLM output passed directly to eval(), exec(), or a shell command — critical RCE risk; never execute LLM-generated text without strict validation and sandboxing.",
        "import_context": None,
    },
    {
        "pattern": r'open\s*\([^)]*(?:response|output|completion|generated|llm)[^)]*["\']w["\']|\.write\s*\(\s*(?:response|output|result|completion|generated)',
        "category": "Security",
        "provider_or_lib": "llm_output_file_write",
        "capability": "LLM Output Written to File",
        "base_severity": 2,
        "description": "LLM output written directly to a file without validation — an attacker could inject path traversal sequences; validate and sanitise before writing.",
        "import_context": r"openai|anthropic|langchain|litellm|\bllm\b|LLM|genai|cohere|mistral|groq",
    },
    # ── Jailbreak / System Prompt Protection ─────────────────────
    {
        "pattern": r"(?i)ignore\s+(?:previous|prior|above|all)\s+instructions|forget\s+(?:your|all|previous)\s+instructions|you\s+are\s+now\s+(?:a\s+)?(?:evil|unrestricted|jailbroken|DAN)",
        "category": "Security",
        "provider_or_lib": "jailbreak_pattern",
        "capability": "Jailbreak Pattern in Codebase",
        "base_severity": 2,
        "description": "Jailbreak or prompt override instruction found in source code — if hardcoded into prompts it bypasses safety guardrails; ensure this is test-only content.",
        "import_context": None,
    },
    {
        "pattern": r"(?i)(?:print|log|return|display|show)\s*\(\s*(?:system_prompt|system_message|SYSTEM_PROMPT|_system)\b",
        "category": "Security",
        "provider_or_lib": "prompt_leakage",
        "capability": "System Prompt Leakage Risk",
        "base_severity": 2,
        "description": "System prompt printed, logged, or returned to the user — system prompts often contain business logic or security rules that must not be disclosed to end users.",
        "import_context": None,
    },
    {
        "pattern": r"system_prompt\s*=\s*['\"][^'\"]{10,}['\"].*\+.*(?:user_input|prompt|query|message|request)",
        "category": "Security",
        "provider_or_lib": "system_prompt_injection",
        "capability": "System Prompt Concatenation Risk",
        "base_severity": 2,
        "description": "System prompt concatenated with user input — use the roles API (system/user message separation) instead of string concatenation to prevent context injection.",
        "import_context": r"openai|anthropic|langchain|litellm|\bllm\b|LLM|genai|cohere|mistral|groq",
    },
    # ── Agent / Agentic Risks ─────────────────────────────────────
    {
        "pattern": r"max_iterations\s*=\s*(?:[1-9]\d{2,}|None)|max_steps\s*=\s*(?:[1-9]\d{2,}|None)",
        "category": "Security",
        "provider_or_lib": "agent_loop_risk",
        "capability": "Unbounded Agent Loop",
        "base_severity": 2,
        "description": "LLM agent without a low iteration cap — adversarial input can cause runaway agent loops with unbounded API costs; set max_iterations <= 10.",
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent|AgentExecutor",
    },
    {
        "pattern": r"(?:requests\.(?:get|post|put|patch)|httpx\.|aiohttp\.)\s*\(\s*[^)]*(?:url|link|href|endpoint)[^)]*\{",
        "category": "Security",
        "provider_or_lib": "ssrf_via_llm_tool",
        "capability": "SSRF Risk via LLM-Controlled URL",
        "base_severity": 1,
        "description": "HTTP request made with an LLM-controlled URL — without an allowlist this enables Server-Side Request Forgery (SSRF); validate URLs against an allowlist before fetching.",
        "import_context": r"langchain|Tool|BaseTool|StructuredTool|agent|\bllm\b|LLM",
    },
    {
        "pattern": r"(?:memory|chat_history|buffer)\s*\.(?:add|save|append|update)\s*\([^)]*(?:user_input|query|message|request)",
        "category": "Security",
        "provider_or_lib": "memory_injection",
        "capability": "Unsanitised Input Stored in Agent Memory",
        "base_severity": 2,
        "description": "Unsanitised user input stored in agent memory — a prompt injection persisted in memory affects all future interactions in the session.",
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|ConversationBuffer|memory",
    },
    {
        "pattern": r"human_approval\s*=\s*False|require_approval\s*=\s*False|auto_approve\s*=\s*True|skip_confirmation\s*=\s*True",
        "category": "Security",
        "provider_or_lib": "no_human_in_loop",
        "capability": "Human-in-the-Loop Disabled",
        "base_severity": 2,
        "description": "Human approval explicitly disabled for an autonomous agent — high-impact actions should require human confirmation before execution.",
        "import_context": None,
    },
    # ── Data Privacy ─────────────────────────────────────────────
    {
        "pattern": r"(?i)(?:ssn|social.?security|credit.?card|cvv|date.?of.?birth|\bdob\b|passport|driver.?licen[sc]e|bank.?account|health.?record|\bphi\b|\bpii\b)[^=\n]*(?:prompt|message|query|send|inject|append)",
        "category": "Security",
        "provider_or_lib": "pii_in_prompt",
        "capability": "PII Sent to LLM",
        "base_severity": 1,
        "description": "PII or sensitive personal data appears to be sent to an LLM API — ensure PII is masked or anonymised before transmission; review data processing agreements.",
        "import_context": r"openai|anthropic|langchain|litellm|\bllm\b|LLM|genai|cohere|mistral|groq",
    },
    {
        "pattern": r"(?:add_documents?|add_texts?|from_documents?|embed_documents?|upsert)\s*\([^)]*(?:user_input|request\.body|request\.json|request\.form|req\.body)",
        "category": "Security",
        "provider_or_lib": "rag_data_poisoning",
        "capability": "RAG Data Poisoning Risk",
        "base_severity": 2,
        "description": "User-controlled input added directly to a vector store — an attacker can poison the knowledge base with adversarial content that manipulates future LLM responses.",
        "import_context": r"langchain|llama_index|haystack|chromadb|pinecone|weaviate|faiss|qdrant|openai",
    },
    # ── Supply Chain / Model Integrity ───────────────────────────
    {
        "pattern": r"from_pretrained\s*\(\s*['\"][^'\"]+['\"]\s*\)",
        "category": "Security",
        "provider_or_lib": "unpinned_model",
        "capability": "Unpinned Model Version",
        "base_severity": 3,
        "description": "Model loaded from Hub without pinning to a specific revision or commit hash — a compromised model update could introduce malicious behaviour; pin with revision='<commit-sha>'.",
        "import_context": r"from\s+transformers|import\s+transformers|from\s+diffusers|import\s+diffusers",
    },
    # ── Telemetry / Data Exfiltration ────────────────────────────
    {
        "pattern": r"LANGCHAIN_TRACING_V2\s*=\s*['\"]?true['\"]?|langsmith|LANGCHAIN_API_KEY\s*=",
        "category": "Security",
        "provider_or_lib": "langchain_telemetry",
        "capability": "LangChain Telemetry / LangSmith Tracing Enabled",
        "base_severity": 2,
        "description": "LangChain telemetry or LangSmith tracing is enabled — all prompts and responses are sent to LangSmith servers; disable in production unless data processing agreements are in place.",
        "import_context": None,
    },
    # ── Hallucination / Reliability Guardrails ───────────────────
    {
        "pattern": r"temperature\s*=\s*(?:0\.[5-9]|1\.?[0-9]?|2\.?0?)\b",
        "category": "Security",
        "provider_or_lib": "high_temperature",
        "capability": "High LLM Temperature",
        "base_severity": 3,
        "description": "LLM temperature above 0.5 increases hallucination risk and output unpredictability; for production reliability use temperature <= 0.2.",
        "import_context": r"openai|anthropic|langchain|litellm|\bllm\b|LLM|genai|cohere|mistral|groq|ChatOpenAI",
    },
]

# ── 8. JavaScript / TypeScript AI usage ─────────────────────────
JS_TS_PATTERNS: List[Dict[str, Any]] = [
    # OpenAI JS/TS SDK
    {
        "pattern": r"from\s+[\"']openai[\"']|require\([\"']openai[\"']\)|new\s+OpenAI\(|new\s+AzureOpenAI\(|openai\.chat\.completions\.create|openai\.completions\.create",
        "category": "External AI API",
        "provider_or_lib": "openai_js",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "OpenAI JS/TS SDK is used — ensure the API key is stored in environment variables and not bundled into client-side code.",
        "import_context": None,
    },
    # Anthropic JS/TS SDK
    {
        "pattern": r"from\s+[\"']@anthropic-ai/sdk[\"']|require\([\"']@anthropic-ai/sdk[\"']\)|new\s+Anthropic\(|anthropic\.messages\.create",
        "category": "External AI API",
        "provider_or_lib": "anthropic_js",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "Anthropic JS/TS SDK is used — ensure the API key is not hardcoded or exposed in frontend bundles.",
        "import_context": None,
    },
    # Google AI / Gemini JS SDK
    {
        "pattern": r"from\s+[\"']@google/generative-ai[\"']|require\([\"']@google/generative-ai[\"']\)|new\s+GoogleGenerativeAI\(|genAI\.getGenerativeModel",
        "category": "External AI API",
        "provider_or_lib": "google_ai_js",
        "capability": "LLM/Completion",
        "base_severity": 2,
        "description": "Google Generative AI JS/TS SDK is used — confirm GCP data residency requirements and that the API key is server-side only.",
        "import_context": None,
    },
    # Vercel AI SDK
    {
        "pattern": r"from\s+[\"']ai[\"']|from\s+[\"']@ai-sdk/|require\([\"']ai[\"']\)|streamText\(|generateText\(|useChat\(|useCompletion\(",
        "category": "External AI API",
        "provider_or_lib": "vercel_ai_sdk",
        "capability": "LLM Streaming/Completion",
        "base_severity": 2,
        "description": "Vercel AI SDK is used — review which underlying provider is configured and ensure the API key is not exposed to the browser.",
        "import_context": None,
    },
    # LangChain JS
    {
        "pattern": r"from\s+[\"']langchain[\"']|from\s+[\"']@langchain/|require\([\"']langchain[\"']\)|new\s+ChatOpenAI\(|new\s+ChatAnthropic\(|new\s+LLMChain\(",
        "category": "External AI API",
        "provider_or_lib": "langchain_js",
        "capability": "LLM Orchestration",
        "base_severity": 2,
        "description": "LangChain JS/TS framework is used — audit which underlying providers and tools are wired in and confirm each is approved.",
        "import_context": None,
    },
    # OpenAI key in JS (process.env pattern) — correct practice, informational only
    {
        "pattern": r"process\.env\.OPENAI_API_KEY|process\.env\.ANTHROPIC_API_KEY|process\.env\.GEMINI_API_KEY|process\.env\.COHERE_API_KEY",
        "category": "External AI API",
        "provider_or_lib": "js_env_key_ref",
        "capability": "API Key via Environment",
        "base_severity": 4,
        "description": "AI API key is correctly read from process.env — confirm the variable is injected at runtime and is never hardcoded as a fallback (e.g. process.env.KEY || 'sk-...').",
        "import_context": None,
    },
    # Hardcoded key in JS/TS
    {
        "pattern": r"(apiKey|api_key|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*[:=]\s*[\"'](sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_\-]{20,})[\"']",
        "category": "Security",
        "provider_or_lib": "js_hardcoded_key",
        "capability": "Secret Exposure",
        "base_severity": 1,
        "description": "An AI API key is hardcoded in JS/TS source — remove immediately, rotate the key, and inject it via environment variables at runtime.",
        "import_context": None,
    },
    # Next.js / React AI route handlers
    {
        "pattern": r"export\s+(async\s+)?function\s+(POST|GET)\s*\(|app/api/.*route\.(ts|js)|pages/api/.*\.(ts|js)",
        "category": "External AI API",
        "provider_or_lib": "nextjs_ai_route",
        "capability": "AI API Route",
        "base_severity": 3,
        "description": "A Next.js API route handling AI calls was found — ensure authentication middleware is applied and rate limiting is in place.",
        "import_context": r"from\s+[\"'](openai|ai|@anthropic|langchain|@google)",
    },
]

# ── 9. Configuration & Infrastructure AI patterns ────────────────
CONFIG_PATTERNS: List[Dict[str, Any]] = [
    # .env file AI keys
    {
        "pattern": r"^(OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY|HF_TOKEN|MISTRAL_API_KEY|GROQ_API_KEY|TOGETHER_API_KEY|GEMINI_API_KEY|REPLICATE_API_TOKEN|AI21_API_KEY|VOYAGE_API_KEY)\s*=\s*.+",
        "category": "Security",
        "provider_or_lib": "env_file_key",
        "capability": "Secret in Config File",
        "base_severity": 2,
        "entropy_guard": True,
        "description": "An AI API key is defined in a .env or config file — verify this file is in .gitignore and never committed to the repository.",
        "import_context": None,
    },
    # docker-compose AI environment variables
    {
        "pattern": r"(OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|GEMINI_API_KEY|COHERE_API_KEY):",
        "category": "Security",
        "provider_or_lib": "docker_compose_key",
        "capability": "Secret in Container Config",
        "base_severity": 2,
        "entropy_guard": True,
        "description": "An AI API key is referenced in a Docker Compose file — use Docker secrets or a secrets manager instead of plaintext environment variables.",
        "import_context": None,
    },
    # Terraform / HCL AI service resources
    {
        "pattern": r'resource\s+"(azurerm_cognitive_account|google_vertex_ai|aws_sagemaker|aws_bedrock|openai_|anthropic_)',
        "category": "External AI API",
        "provider_or_lib": "terraform_ai_resource",
        "capability": "Cloud AI Service (IaC)",
        "base_severity": 3,
        "description": "A Terraform resource for a cloud AI service was found — ensure access policies, logging, and data residency are configured correctly.",
        "import_context": None,
    },
    # Kubernetes / Helm AI model serving
    {
        "pattern": r"(ollama|vllm|triton-inference|torchserve|seldon|kserve|ray-serve)\s*:(?!/)",
        "category": "Local LLM Runtime",
        "provider_or_lib": "k8s_model_serving",
        "capability": "Model Serving (Kubernetes)",
        "base_severity": 3,
        "description": "A Kubernetes-based model serving stack was found in config — confirm the inference endpoint is not publicly exposed and resource quotas are set.",
        "import_context": None,
    },
    # pyproject.toml / requirements.txt AI dependencies
    {
        "pattern": r"(openai|anthropic|langchain|llama[_-]index|transformers|diffusers|cohere|mistralai|groq|together|google-generativeai|litellm|autogen|crewai|semantic-kernel)\s*(>=|==|~=|>|<|\[)",
        "category": "External AI API",
        "provider_or_lib": "dependency_declaration",
        "capability": "AI Dependency",
        "base_severity": 4,
        "description": "An AI library is declared as a project dependency — confirm the version is pinned and the library is on the approved list.",
        "import_context": None,
    },
    # GitHub Actions AI secrets usage — correct practice, informational only
    {
        "pattern": r"\$\{\{\s*secrets\.(OPENAI_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|GEMINI_API_KEY|COHERE_API_KEY|MISTRAL_API_KEY)\s*\}\}",
        "category": "External AI API",
        "provider_or_lib": "ci_secret_ref",
        "capability": "CI/CD Secret Reference",
        "base_severity": 4,
        "description": "An AI API key is correctly injected from CI/CD secrets — verify the secret is scoped to the minimum required jobs and branches, and that no job logs or artifacts echo the value.",
        "import_context": None,
    },
    # Model names in YAML config — exclude comment lines
    {
        "pattern": r"(?m)^(?![ \t]*#)[ \t]*model\s*:\s*[\"']?(gpt-4|gpt-3\.5|claude-[23456]|gemini-|llama-[23]|mistral-|mixtral-)[^\s\"'\n]*",
        "category": "External AI API",
        "provider_or_lib": "model_name_in_config",
        "capability": "Model Reference",
        "base_severity": 4,
        "description": "A specific AI model name is hardcoded in a config file — move model selection to an environment variable so it can be changed without a code deployment.",
        "import_context": None,
    },
]

# ── 10. Agent Frameworks & AI Proxy/Gateway ──────────────────────
AGENT_PATTERNS: List[Dict[str, Any]] = [
    # LiteLLM (proxy / unified gateway)
    {
        "pattern": r"from\s+litellm\s+import|import\s+litellm|litellm\.completion\(|litellm\.acompletion\(|LiteLLM\(",
        "category": "AI Proxy/Gateway",
        "provider_or_lib": "litellm",
        "capability": "LLM Proxy/Gateway",
        "base_severity": 3,
        "description": "LiteLLM proxy/gateway is used — verify the routing config does not silently forward requests to unapproved providers.",
        "import_context": None,
    },
    # Portkey
    {
        "pattern": r"from\s+portkey_ai\s+import|import\s+portkey_ai|Portkey\(|PORTKEY_API_KEY|portkey\.ai",
        "category": "AI Proxy/Gateway",
        "provider_or_lib": "portkey",
        "capability": "LLM Gateway",
        "base_severity": 3,
        "description": "Portkey AI gateway is used — ensure the gateway is configured to enforce data residency and provider allowlists.",
        "import_context": None,
    },
    # Helicone
    {
        "pattern": r"helicone\.ai|HELICONE_API_KEY|x-helicone-auth|openai\.helicone",
        "category": "AI Proxy/Gateway",
        "provider_or_lib": "helicone",
        "capability": "LLM Observability Proxy",
        "base_severity": 3,
        "description": "Helicone observability proxy is used — all prompts and responses pass through a third-party service; confirm this is compliant with data classification policy.",
        "import_context": None,
    },
    # AutoGen
    {
        "pattern": r"from\s+autogen\s+import|import\s+autogen|AssistantAgent\(|UserProxyAgent\(|GroupChat\(|ConversableAgent\(",
        "category": "Agent Framework",
        "provider_or_lib": "autogen",
        "capability": "Multi-Agent Orchestration",
        "base_severity": 2,
        "description": "Microsoft AutoGen multi-agent framework is used — agent-to-agent communication may execute arbitrary code; ensure code execution sandboxing and human-in-the-loop controls are configured.",
        "import_context": None,
    },
    # CrewAI
    {
        "pattern": r"from\s+crewai\s+import|import\s+crewai|Crew\(|Agent\(.*role=|Task\(.*description=|Process\.sequential|Process\.hierarchical",
        "category": "Agent Framework",
        "provider_or_lib": "crewai",
        "capability": "Multi-Agent Orchestration",
        "base_severity": 2,
        "description": "CrewAI agent framework is used — review the tools granted to each agent and ensure no agent has unrestricted file system or network access.",
        "import_context": None,
    },
    # Semantic Kernel
    {
        "pattern": r"from\s+semantic_kernel\s+import|import\s+semantic_kernel|Kernel\(\)|kernel\.add_plugin|KernelPlugin|sk\.Kernel",
        "category": "Agent Framework",
        "provider_or_lib": "semantic_kernel",
        "capability": "Agent/Plugin Orchestration",
        "base_severity": 2,
        "description": "Microsoft Semantic Kernel is used — audit registered plugins for unsafe capabilities and validate that memory stores do not retain sensitive conversation history.",
        "import_context": None,
    },
    # LangGraph
    {
        "pattern": r"from\s+langgraph\s+import|import\s+langgraph|StateGraph\(|CompiledGraph|add_node\(|add_edge\(.*langgraph",
        "category": "Agent Framework",
        "provider_or_lib": "langgraph",
        "capability": "Stateful Agent Graph",
        "base_severity": 2,
        "description": "LangGraph stateful agent framework is used — review graph node logic for unsafe tool calls and ensure the state schema does not persist PII across sessions.",
        "import_context": None,
    },
    # OpenAI Assistants / Function Calling
    {
        "pattern": r"client\.beta\.assistants|assistants\.create|threads\.create|runs\.create|tool_choice\s*=|function_call\s*=|\"type\"\s*:\s*\"function\"",
        "category": "Agent Framework",
        "provider_or_lib": "openai_assistants",
        "capability": "OpenAI Assistants / Function Calling",
        "base_severity": 2,
        "description": "OpenAI Assistants API or function calling is used — audit every registered function/tool for security implications and ensure the model cannot trigger destructive operations.",
        "import_context": None,
    },
    # Dify / Flowise / n8n (no-code AI orchestration)
    {
        "pattern": r"dify\.ai|DIFY_API_KEY|flowise|n8n.*openai|n8n.*anthropic|langflow",
        "category": "AI Proxy/Gateway",
        "provider_or_lib": "nocode_ai_platform",
        "capability": "No-code AI Platform",
        "base_severity": 3,
        "description": "A no-code AI orchestration platform (Dify/Flowise/n8n/Langflow) is referenced — ensure the platform instance is self-hosted or approved, and that data classification is reviewed.",
        "import_context": None,
    },
    # AWS Bedrock
    {
        "pattern": r"bedrock-runtime|invoke_model.*bedrock|BedrockChat\(|BedrockLLM\(|anthropic\.claude.*bedrock|amazon\.titan|amazon\.nova",
        "category": "External AI API",
        "provider_or_lib": "aws_bedrock",
        "capability": "LLM/Completion (AWS Bedrock)",
        "base_severity": 3,
        "description": "AWS Bedrock is used for model inference — confirm the IAM role has least-privilege permissions and that prompt logging to CloudWatch is intentional.",
        "import_context": None,
    },
    # Azure AI Foundry / AI Studio
    {
        "pattern": r"azure\.ai\.inference|AzureAIClient\(|ChatCompletionsClient\(|azure\.ai\.projects|AIProjectClient\(",
        "category": "External AI API",
        "provider_or_lib": "azure_ai_foundry",
        "capability": "LLM/Completion (Azure AI Foundry)",
        "base_severity": 3,
        "description": "Azure AI Foundry / AI Studio SDK is used — verify the deployment endpoint, content filters, and data handling comply with corporate Azure policy.",
        "import_context": None,
    },
]

# ── 11. Infrastructure-as-Code AI patterns (Task 7) ──────────────
INFRA_PATTERNS: List[Dict[str, Any]] = [
    # AWS CDK — Python
    {
        "pattern": r"(bedrock|SageMaker|ComprehendClient|RekognitionClient"
                   r"|TranslateClient|TextractClient|PollyClient|LexModelBuilding"
                   r"|BedrockRuntime|BedrockClient)\s*[\(\.]",
        "category": "Infrastructure AI Config",
        "provider_or_lib": "aws_cdk_ai",
        "capability": "AWS AI Service (CDK)",
        "base_severity": 3,
        "description": "An AWS AI/ML service is provisioned via CDK — verify IAM permissions are least-privilege and data processing agreements are in place.",
        "import_context": r"(aws_cdk|constructs|from aws_cdk|import aws_cdk|@aws-cdk)",
    },
    # AWS CDK — TypeScript/JavaScript
    {
        "pattern": r"new\s+(bedrock|Bedrock|SageMaker|sagemaker|Comprehend|Rekognition"
                   r"|Translate|Textract|Polly|Lex)\.",
        "category": "Infrastructure AI Config",
        "provider_or_lib": "aws_cdk_ai",
        "capability": "AWS AI Service (CDK TypeScript)",
        "base_severity": 3,
        "description": "An AWS AI/ML service is provisioned via CDK (TypeScript) — verify IAM roles and data-handling policies.",
        "import_context": r"(@aws-cdk|aws-cdk-lib|constructs)",
    },
    # Pulumi — Python
    {
        "pattern": r"pulumi_aws\.(sagemaker|bedrock|comprehend|rekognition|translate"
                   r"|textract|lex)|pulumi_azure\.(cognitive|openai|machine_learning"
                   r"|bot_service)|pulumi_gcp\.(vertex_ai|ml_engine|dialogflow)",
        "category": "Infrastructure AI Config",
        "provider_or_lib": "pulumi_ai",
        "capability": "Cloud AI Resource (Pulumi)",
        "base_severity": 3,
        "description": "A cloud AI service is defined via Pulumi — confirm the resource configuration, IAM bindings, and data classification are reviewed.",
        "import_context": r"import pulumi|from pulumi",
    },
    # Pulumi — YAML
    {
        "pattern": r"type:\s*(aws:sagemaker|aws:bedrock|azure:cognitive|azure:openai"
                   r"|gcp:vertex|gcp:ml|aws:comprehend|aws:rekognition)",
        "category": "Infrastructure AI Config",
        "provider_or_lib": "pulumi_ai",
        "capability": "Cloud AI Resource (Pulumi YAML)",
        "base_severity": 3,
        "description": "A cloud AI resource type is referenced in a Pulumi YAML stack — review configuration and access controls.",
        "import_context": None,
    },
    # Helm values.yaml — model serving / AI config
    # Note: generic key names (OPENAI_API_KEY etc.) removed — covered by hardcoded_key
    # with entropy guard. This pattern targets model/serving config only.
    {
        "pattern": r"(modelName|model_name|openaiKey|openai_key|anthropicKey"
                   r"|triton|torchserve|seldon|kserve|bentoml)\s*:",
        "category": "Infrastructure AI Config",
        "provider_or_lib": "helm_ai_values",
        "capability": "AI Config in Helm values",
        "base_severity": 3,
        "path_context": r"(helm|chart|values\.ya?ml)",
        "description": "An AI model name or serving-stack key is present in Helm values — ensure secrets are stored in a secrets manager (e.g. Vault, AWS Secrets Manager) and not in plain values.yaml.",
        "import_context": None,
    },
    # Ansible — AI-related tasks / vars
    # Note: bare key names removed — they fire on any YAML.
    # This pattern now only triggers on Ansible-specific constructs.
    {
        "pattern": r"(pip install openai|pip install anthropic|pip install langchain"
                   r"|ansible\.builtin\.(pip|command|shell).*openai"
                   r"|ansible\.builtin\.(pip|command|shell).*anthropic)",
        "category": "Infrastructure AI Config",
        "provider_or_lib": "ansible_ai",
        "capability": "AI Dependency in Ansible",
        "base_severity": 3,
        "path_context": r"(ansible|playbook|roles|tasks|vars|handlers)",
        "description": "An AI library is installed via an Ansible task — document this dependency and ensure API keys are encrypted with ansible-vault, not stored in plain vars.",
        "import_context": None,
    },
    # Kustomize / raw Kubernetes manifests — model serving
    # Note: generic key names removed — covered by hardcoded_key with entropy guard.
    # This pattern only triggers on K8s/serving-specific annotations and controllers.
    {
        "pattern": r"(kserve\.io|serving\.knative\.dev|seldon\.io|ray\.io/cluster)",
        "category": "Infrastructure AI Config",
        "provider_or_lib": "k8s_ai_manifest",
        "capability": "AI Serving in Kubernetes Manifest",
        "base_severity": 3,
        "path_context": r"(^|[\\/])(manifests?|k8s|kubernetes|kustomize|deploy(?:ments?)?|overlays?|bases?)[\\/]",
        "description": "A Kubernetes AI model serving component is referenced in a manifest — confirm the inference endpoint is not publicly exposed and resource quotas are set.",
        "import_context": None,
    },
]

# ── 7e. DeepTeam-derived vulnerability patterns ──────────────────
# Six vulnerability classes from DeepTeam mapped to static detectable code patterns.
# References: https://github.com/confident-ai/deepteam
# Coverage: IndirectInstruction, ToolMetadataPoisoning, InsecureInterAgentCommunication,
#           AutonomousAgentDrift, UnexpectedCodeExecution (new sub-types), ExcessiveAgency (new sub-types)

DEEPTEAM_PATTERNS: List[Dict[str, Any]] = [

    # ── IndirectInstruction / RAG Injection ───────────────────────
    # Unsanitised tool output fed back into a prompt (tool_output_injection)
    {
        "pattern": (
            r"(?:tool_result|tool_output|function_result|observation|action_result)"
            r"\s*[\+\s]*(?:messages|prompt|content|system)\b"
            r"|(?:messages|prompt|content)\s*[\+\s]*"
            r"(?:tool_result|tool_output|function_result|observation|action_result)"
        ),
        "category": "Security",
        "provider_or_lib": "tool_output_injection",
        "capability": "Indirect Instruction — Tool Output Injection",
        "base_severity": 2,
        "description": (
            "Tool/function output concatenated directly into a prompt or message list "
            "without sanitisation — an attacker who controls tool responses can inject "
            "instructions that redirect the agent's behaviour (indirect prompt injection). "
            "Treat all tool outputs as untrusted; validate and escape before inclusion."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent|BaseTool|StructuredTool",
    },

    # Document-embedded instructions: loading file/document content straight into a prompt
    {
        "pattern": (
            r"(?:open|read_text|read_file|load_document|Document)\s*\([^)]+\)"
            r".*?(?:prompt|messages|system_prompt|user_message)"
            r"|(?:prompt|messages|system_prompt|user_message)"
            r".*?(?:open|read_text|read_file|load_document|Document)\s*\("
        ),
        "category": "Security",
        "provider_or_lib": "document_embedded_instruction",
        "capability": "Indirect Instruction — Document-Embedded Instructions",
        "base_severity": 2,
        "description": (
            "File or document content loaded directly into a prompt — documents from "
            "untrusted sources may contain embedded instructions (e.g. hidden text, "
            "footnotes) that hijack the agent's actions. Sanitise or summarise document "
            "content before injection into the prompt context."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent",
    },

    # Cross-content / session injection: referencing previous context to persist instructions
    {
        "pattern": (
            r"(?:ConversationBuffer|ConversationSummary|memory\.load_memory|"
            r"chat_history\.messages|previous_messages|session_state)\s*"
            r"[^\n]*(?:prompt|messages|content)"
        ),
        "category": "Security",
        "provider_or_lib": "cross_context_injection",
        "capability": "Indirect Instruction — Cross-Context Injection",
        "base_severity": 2,
        "description": (
            "Conversation history or session memory injected into the active prompt "
            "context without a trust boundary — a poisoned prior turn can carry "
            "instructions into future interactions (cross-context injection). "
            "Validate and sanitise stored context before reuse."
        ),
        "import_context": r"langchain|openai|anthropic|\bllm\b|LLM|ConversationBuffer|memory",
    },

    # ── ToolMetadataPoisoning / Schema Manipulation ───────────────
    # Tool schema or description built from external/user-controlled data
    {
        "pattern": (
            r"(?:Tool|BaseTool|StructuredTool|tool_from_function)\s*\("
            r"[^)]*(?:description|args_schema)\s*=\s*"
            r"(?![\"\'][^\"\']+[\"\'])"  # not a string literal — dynamic value
            r"[A-Za-z_]"                 # variable / expression
        ),
        "category": "Security",
        "provider_or_lib": "tool_schema_manipulation",
        "capability": "Tool Metadata Poisoning — Dynamic Schema/Description",
        "base_severity": 2,
        "description": (
            "LLM tool description or schema constructed from a variable rather than a "
            "string literal — if this value originates from external input or a registry "
            "it can be poisoned to misrepresent tool permissions or deceive the model "
            "into unsafe usage (tool metadata poisoning). Use only hardcoded, reviewed "
            "tool descriptions."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|BaseTool|StructuredTool",
    },

    # Tool loaded dynamically from a registry or external source (registry poisoning)
    {
        "pattern": (
            r"(?:load_tools|get_tool|tool_registry\.get|registry\[|tools\.get)\s*\("
            r"[^)]*(?:request\.|user_|input|config\[|environ)"
        ),
        "category": "Security",
        "provider_or_lib": "tool_registry_poisoning",
        "capability": "Tool Metadata Poisoning — Registry Poisoning Risk",
        "base_severity": 2,
        "description": (
            "Tool loaded from a registry using a user-supplied or config-derived "
            "identifier — without signature verification a compromised registry entry "
            "can substitute a malicious tool. Allowlist permitted tool names and "
            "verify tool integrity before loading."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM",
    },

    # ── InsecureInterAgentCommunication ───────────────────────────
    # Agent-to-agent message passing without any validation
    {
        "pattern": (
            r"(?:agent\.run|agent\.invoke|agent\.chat|agent\.step|"
            r"sub_agent\.|child_agent\.|delegate_to|handoff_to|transfer_to)"
            r"\s*\([^)]*(?:output|result|response|message|content)"
        ),
        "category": "Security",
        "provider_or_lib": "insecure_inter_agent_msg",
        "capability": "Insecure Inter-Agent Communication — Unvalidated Message Passing",
        "base_severity": 2,
        "description": (
            "Agent output passed directly to another agent without validation or "
            "sanitisation — a compromised sub-agent can inject instructions into the "
            "parent agent's context (agent-in-the-middle / message injection). "
            "Validate all inter-agent messages against an expected schema before use."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent|AgentExecutor",
    },

    # Spawning child agents with inherited permissions
    {
        "pattern": (
            r"(?:AgentExecutor|initialize_agent|create_react_agent|create_openai_functions_agent)"
            r"\s*\([^)]*tools\s*=\s*tools\b"   # reuses parent tool list unchanged
        ),
        "category": "Security",
        "provider_or_lib": "agent_permission_inheritance",
        "capability": "Insecure Inter-Agent Communication — Unrestricted Permission Inheritance",
        "base_severity": 2,
        "description": (
            "Child agent initialised with the same full tool set as the parent — "
            "sub-agents should receive only the minimal tools needed for their "
            "subtask. Unrestricted tool inheritance violates least-privilege and "
            "enables privilege escalation across the agent hierarchy."
        ),
        "import_context": r"langchain|openai|anthropic|\bllm\b|LLM|AgentExecutor",
    },

    # ── AutonomousAgentDrift ──────────────────────────────────────
    # Runaway autonomy: infinite loop or no termination condition
    {
        "pattern": (
            r"while\s+True\s*:[\s\S]{0,120}"
            r"(?:agent\.|\.run\(|\.step\(|\.invoke\(|chain\.)"
        ),
        "category": "Security",
        "provider_or_lib": "agent_runaway_autonomy",
        "capability": "Autonomous Agent Drift — Runaway Autonomy (Infinite Loop)",
        "base_severity": 1,
        "description": (
            "LLM agent called inside an infinite loop with no explicit break condition "
            "— this enables runaway autonomy where the agent takes unbounded actions "
            "and incurs unlimited cost. Add a maximum iteration counter and a human "
            "checkpoint for long-running loops."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent|AgentExecutor",
    },

    # Reward hacking: agent optimising proxy metrics (score/reward signals exposed to LLM)
    {
        "pattern": (
            r"(?:reward|score|metric|fitness|eval_score)\s*=\s*"
            r"(?:llm\.|chain\.|agent\.|completion\.|response\.)"
        ),
        "category": "Security",
        "provider_or_lib": "agent_reward_hacking",
        "capability": "Autonomous Agent Drift — Reward / Metric Hacking Risk",
        "base_severity": 3,
        "description": (
            "An LLM output is assigned directly as a reward, score, or fitness metric "
            "— if the agent can observe its own evaluation signal it may learn to "
            "optimise the proxy rather than the true objective (reward hacking / "
            "goal drift). Keep evaluation logic separate from the model's observable "
            "context."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent",
    },

    # Agent collusion: multiple agents sharing a mutable global state without locks
    {
        "pattern": (
            r"(?:shared_memory|global_state|shared_context|shared_store)"
            r"\s*[\.\[].*?(?:update|append|set|write|put)\s*\("
        ),
        "category": "Security",
        "provider_or_lib": "agent_collusion_risk",
        "capability": "Autonomous Agent Drift — Agent Collusion via Shared State",
        "base_severity": 2,
        "description": (
            "Multiple agents writing to a shared mutable store without access controls "
            "— one agent can corrupt the shared context to influence another agent's "
            "decisions (agent collusion). Use isolated per-agent memory and require "
            "explicit authorisation for cross-agent writes."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent",
    },

    # ── UnexpectedCodeExecution (new sub-types) ───────────────────
    # Shell command execution via agent-generated strings (shell_command_execution)
    {
        "pattern": (
            r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\("
            r"[^)]*(?:response|output|result|completion|generated|llm_out|agent_out)"
        ),
        "category": "Security",
        "provider_or_lib": "shell_cmd_from_llm",
        "capability": "Unexpected Code Execution — Shell Command from LLM Output",
        "base_severity": 1,
        "description": (
            "LLM or agent output passed directly to subprocess — critical RCE risk. "
            "An adversarial prompt can inject arbitrary shell commands; never pass "
            "LLM-generated strings to subprocess without strict allowlist validation "
            "and sandboxing."
        ),
        "import_context": None,
    },

    # Eval usage on LLM output (eval_usage — more specific than existing insecure_output_handling)
    {
        "pattern": (
            r"(?:eval|exec|compile)\s*\(\s*"
            r"(?:response|output|result|completion|answer|llm_output|generated|agent_output)"
            r"(?:\.(?:text|content|strip|lower|upper|replace)\s*\(\s*\))?"
            r"\s*[,\)]"
        ),
        "category": "Security",
        "provider_or_lib": "eval_on_llm_output",
        "capability": "Unexpected Code Execution — eval/exec on LLM Output",
        "base_severity": 1,
        "description": (
            "eval() or exec() called on LLM/agent output — allows arbitrary Python "
            "code execution if an attacker can influence the model's response. "
            "Use ast.literal_eval() for data parsing, or a sandboxed interpreter "
            "such as RestrictedPython for legitimate code-generation use cases."
        ),
        "import_context": None,
    },

    # Dynamic code generation written to file then executed (unauthorised code execution)
    {
        "pattern": (
            r"(?:open|write_text|write_bytes)\s*\([^)]*\bw\b[^)]*\)"
            r"[\s\S]{0,80}"
            r"(?:subprocess|exec|eval|os\.system|importlib\.import_module)\s*\("
        ),
        "category": "Security",
        "provider_or_lib": "dynamic_code_write_exec",
        "capability": "Unexpected Code Execution — Generated Code Written then Executed",
        "base_severity": 1,
        "description": (
            "Code written to a file and then executed in close proximity — if the "
            "written content is LLM-generated this is a two-stage RCE pattern. "
            "Isolate code generation from execution; sandbox the execution environment "
            "and review generated code before running."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent",
    },

    # ── ExcessiveAgency — new sub-types ──────────────────────────
    # Excessive functionality: tool defined with filesystem or shell access
    {
        "pattern": (
            r"@tool\b[\s\S]{0,300}"
            r"(?:os\.(?:remove|unlink|rmdir|rename|system)|"
            r"shutil\.(?:rmtree|move|copy)|"
            r"subprocess\.|open\s*\([^)]*[\"']w)"
        ),
        "category": "Security",
        "provider_or_lib": "excessive_tool_functionality",
        "capability": "Excessive Agency — Tool with Destructive Filesystem/Shell Access",
        "base_severity": 2,
        "description": (
            "An LLM tool (@tool function) contains filesystem deletion, rename, "
            "or shell execution operations — granting an LLM destructive capabilities "
            "without human approval is excessive agency. Restrict tools to read-only "
            "operations where possible; require explicit confirmation for destructive actions."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|BaseTool|StructuredTool",
    },

    # Excessive permissions: agent granted admin / superuser permissions explicitly
    {
        "pattern": (
            r"(?i)(?:role|permission|access_level|scope|privilege)\s*=\s*"
            r"[\"'](?:admin|root|superuser|super_admin|god|owner|full|all)[\"']"
        ),
        "category": "Security",
        "provider_or_lib": "excessive_agent_permissions",
        "capability": "Excessive Agency — Agent Granted Admin/Superuser Permissions",
        "base_severity": 1,
        "description": (
            "An LLM agent or chain is explicitly assigned admin, root, or superuser "
            "permissions — this violates least-privilege and means a single prompt "
            "injection could lead to full system compromise. Grant agents only the "
            "minimum permissions required for their specific task."
        ),
        "import_context": r"langchain|openai|anthropic|litellm|\bllm\b|LLM|agent|AgentExecutor",
    },

    # Excessive autonomy: no confirmation before irreversible actions
    {
        "pattern": (
            r"(?:confirm|verify|approve|require_approval|human_in_loop)\s*=\s*False"
            r"|(?:skip_confirmation|bypass_approval|auto_execute)\s*=\s*True"
            r"|(?:force\s*=\s*True|dry_run\s*=\s*False)[^\n]*"
            r"(?:delete|drop|truncate|remove|destroy|terminate|shutdown|kill)"
        ),
        "category": "Security",
        "provider_or_lib": "excessive_agent_autonomy",
        "capability": "Excessive Agency — Irreversible Action Without Human Confirmation",
        "base_severity": 2,
        "description": (
            "Confirmation or approval explicitly disabled for an operation that could "
            "be irreversible (delete, drop, terminate, etc.) — autonomous agents must "
            "require human confirmation before executing destructive or high-impact "
            "actions. Add a human-in-the-loop checkpoint."
        ),
        "import_context": None,
    },
]

# ── All patterns combined ─────────────────────────────────────────
ALL_PATTERNS: List[Dict[str, Any]] = (
    EXTERNAL_API_PATTERNS
    + LOCAL_LLM_PATTERNS
    + EMBEDDING_PATTERNS
    + RAG_VECTOR_PATTERNS
    + FINETUNING_PATTERNS
    + ML_LIB_PATTERNS
    + SECURITY_PATTERNS
    + DYNAMIC_IMPORT_PATTERNS
    + DATA_EXFIL_PATTERNS
    + MODEL_LOADING_PATTERNS
    + GARAK_PATTERNS
    + GISKARD_PATTERNS
    + PYRIT_PATTERNS
    + DEEPTEAM_PATTERNS
    + JS_TS_PATTERNS
    + CONFIG_PATTERNS
    + AGENT_PATTERNS
    + INFRA_PATTERNS
)

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".pyw", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".rs", ".swift", ".kt", ".scala", ".groovy",
    ".cs", ".cpp", ".c", ".h", ".hpp", ".pl", ".r", ".sql",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".env", ".xml", ".properties",
    ".cfg", ".conf", ".gradle", ".kts",
    ".sh", ".bash", ".ps1",
    ".ipynb",  # notebooks handled specially
    ".tf", ".hcl",  # Terraform (AI service config)
    ".md", ".txt",  # docs referencing endpoints
    ".Dockerfile", "Dockerfile",
    ".mjs", ".cjs",           # ES modules / CommonJS
    ".vue", ".svelte",        # frontend frameworks
    "requirements.txt",       # Python dependency declarations
    "package.json",           # JS dependency declarations
    "pyproject.toml",         # Python project config
    # Task 6: minified bundles
    ".min.js",
    # Task 7: IaC formats
    ".cdk.ts", ".cdk.js",     # AWS CDK (also caught by .ts/.js)
    "Pulumi.yaml",            # Pulumi project file (name-based)
    "Chart.yaml",             # Helm chart descriptor
}

# Files/dirs to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox", "venv", ".venv",
    "env", ".env", "dist", "build", ".idea", ".vscode",
    "*.egg-info", ".pytest_cache", "coverage", ".coverage",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
    "*.map",   # source maps only — *.min.js now scanned (Task 6)
}

# ── Import context guards ─────────────────────────────────────────
# Maps provider_or_lib → regex that must match somewhere in the file
# for the finding to be emitted. Prevents false positives from generic
# tokens (e.g. "pipeline(" without a transformers import).
IMPORT_GUARDS: Dict[str, str] = {
    "transformers":          r"from\s+transformers|import\s+transformers",
    "pytorch":               r"import\s+torch|from\s+torch",
    "tensorflow":            r"import\s+tensorflow|from\s+tensorflow",
    "scikit_learn":          r"from\s+sklearn|import\s+sklearn",
    "xgboost":               r"import\s+xgboost|from\s+xgboost",
    "lightgbm":              r"import\s+lightgbm|from\s+lightgbm",
    "rag_pattern":           r"(langchain|llama_index|haystack|ragas|RetrievalQA|similarity_search)",
    "transformers_trainer":  r"from\s+transformers|import\s+transformers",
    "generic_finetune":      r"(train|finetune|fine_tune)",
    "logging_risk":          r"(openai|anthropic|langchain|litellm|llm|LLM|ChatOpenAI)",
    # unsafe_code_exec: no guard needed
    "sql_injection_risk":    r"(openai|anthropic|langchain|llm|LLM|generate|completion)",
    "debug_mode":            r"(openai|anthropic|langchain|litellm|llm|LLM|transformers|vllm)",
    "weak_config":           r"(openai|anthropic|langchain|litellm|\bllm\b|LLM|transformers|vllm|genai|cohere|mistral|groq)",
    # unsafe_pickle_model: no import guard — pickle.load() is dangerous regardless of context
    "nextjs_ai_route":       r"from\s+[\"'](openai|ai|@anthropic|langchain|@google)",
    # New guards for enhancement patterns
    # unsafe_torch_load: covered by unsafe_torch_load_bare
    # unsafe_tf_load: no guard — tf.saved_model.load dangerous in any context
    "remote_model_load":     r"from\s+transformers|import\s+transformers",
}
