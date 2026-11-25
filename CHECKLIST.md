# AutoSOC Step-by-Step Implementation Master Checklist

This checklist defines every concrete milestone and task required to build the production-grade **AutoSOC** platform from scratch. Each task includes clear acceptance criteria.

---

## Phase 1: Environment Setup, Scaffolding & Infrastructure

- [x] **1.1 Workspace & Tooling Initialization**
  - [x] Initialize Python 3.11+ environment with `uv` or `poetry` / `venv`.
  - [x] Configure `pyproject.toml` with strict linters: `ruff`, `mypy`, `pytest`.
  - [x] Configure `.pre-commit-config.yaml` / tooling for formatting and security scans.
  - [x] Create `.env.example` defining all credentials, ports, and configuration keys.

- [x] **1.2 Containerized Infrastructure (`docker-compose.yml`)**
  - [x] Configure **Qdrant** vector database (port 6333).
  - [x] Configure **Redis** cluster / standalone with persistence enabled (port 6379).
  - [x] Configure **RabbitMQ** with Management Plugin enabled (ports 5672, 15672).
  - [x] Configure self-hosted **Arize Phoenix** for local LLM tracing & observability (port 6006).
  - [x] Verify all services boot cleanly via `docker compose up -d` / `./run.sh` and healthchecks pass.

- [x] **1.3 Base Configuration Module**
  - [x] Implement `src/config.py` using `pydantic-settings` with strict type validation.
  - [x] Add runtime validation verifying connection strings and environment keys.

---

## Phase 2: Dual Protocol Gateway (gRPC & REST)

- [x] **2.1 Protocol Buffers Definition & Code Generation**
  - [x] Author `protos/telemetry.proto` defining `AlertEvent`, `IngestSummary`, and streaming RPCs.
  - [x] Author `protos/incident.proto` defining incident status updates.
  - [x] Create `scripts/generate_protos.sh` to compile `.proto` to Python stubs via `grpcio-tools`.
  - [x] Verify generated stubs compile and import cleanly.

- [x] **2.2 gRPC Telemetry Ingestion Server**
  - [x] Implement `src/api/grpc/telemetry_servicer.py` supporting streaming alert ingestion.
  - [x] Implement mTLS certificate validation for incoming gRPC client connections (`scripts/generate_certs.sh`).
  - [x] Write integration test verifying client-to-server gRPC event streaming (`tests/integration/test_grpc_streaming.py`).

- [x] **2.3 FastAPI REST Gateway**
  - [x] Implement `src/api/rest/app.py` with OpenAPI docs, CORS, and request ID middleware.
  - [x] Implement JWT/OAuth2 bearer authentication middleware (`src/api/rest/middleware/auth.py`).
  - [x] Implement Redis-backed sliding-window rate limiting middleware (`src/api/rest/middleware/rate_limiter.py`).
  - [x] Implement routes:
    - [x] `POST /api/v1/incidents/submit`
    - [x] `GET /api/v1/incidents/{incident_id}`
    - [x] `POST /api/v1/incidents/{incident_id}/approval`
    - [x] `GET /api/v1/incidents/{incident_id}/stream` (SSE)
  - [x] Write tests verifying route responses, authentication rejections, and rate limits (`tests/integration/test_rest_gateway.py`).

---

## Phase 3: Message Queue & Redis Infrastructure

- [x] **3.1 RabbitMQ Event Backbone**
  - [x] Implement `src/queue/rabbitmq_client.py` using `aio-pika`.
  - [x] Declare exchange `soc.events` (topic) and dead-letter exchange `soc.dlx`.
  - [x] Declare queues: `alerts.raw`, `alerts.triage`, `remediation.approval`, `alerts.dead_letter` with `x-max-priority: 10`.
  - [x] Implement message publisher with acknowledgment confirmation (`src/queue/publisher.py`).
  - [x] Implement asynchronous worker consumer pool with consumer prefetch limits (`src/queue/consumer.py`).
  - [x] Test message routing, priority queue jumping, dead-letter fallback, and retry policies (`tests/integration/test_rabbitmq_backbone.py`).

- [ ] **3.2 Redis High-Performance Services**
  - [ ] Implement `src/cache/redis_client.py` using `redis-py` (async).
  - [ ] Implement `src/cache/semantic_cache.py`:
    - [ ] Generate cosine similarity search over cached alert embeddings.
    - [ ] Store and retrieve cached analysis if similarity $\ge 0.94$.
  - [ ] Implement `src/cache/distributed_lock.py` (`Redlock` algorithm) for asset-level mutual exclusion.
  - [ ] Unit test semantic cache hits, misses, and distributed lock acquisition timeouts.

---

## Phase 4: Advanced RAG Engine & Vector Pipeline

- [ ] **4.1 Qdrant Vector DB Client & Collections**
  - [ ] Implement `src/rag/qdrant_client.py` to manage Qdrant collections.
  - [ ] Create hybrid collection with both dense vector (1536/768 dim) and sparse vector configurations.

- [ ] **4.2 Ingestion & Semantic Chunking Pipeline**
  - [ ] Implement `src/rag/ingestion.py` for parsing MITRE ATT&CK docs, NIST guides, and playbooks.
  - [ ] Implement hierarchical chunking with parent-child relationship tracking and metadata enrichment.
  - [ ] Write script `scripts/seed_threat_intel.py` to populate Qdrant with initial security knowledge.

- [ ] **4.3 Hybrid Search & Reciprocal Rank Fusion (RRF)**
  - [ ] Implement dense embedding generation (FastEmbed / HuggingFace / OpenAI).
  - [ ] Implement sparse BM25 token weight generation.
  - [ ] Implement Reciprocal Rank Fusion algorithm to combine dense and sparse rankings.

- [ ] **4.4 Cross-Encoder Re-Ranking & Corrective RAG (CRAG)**
  - [ ] Implement `src/rag/reranker.py` using `FlashRank` or `bge-reranker`.
  - [ ] Implement `src/rag/crag_evaluator.py`:
    - [ ] Score relevance of retrieved context against original threat query.
    - [ ] Trigger automated query reformulation when score $< 0.80$.
  - [ ] Integration test: verify hybrid retrieval + reranker accuracy on sample CVE queries.

---

## Phase 5: Multi-Tier Guardrail Defense Matrix

- [ ] **5.1 Layer 1: Prompt Injection & Jailbreak Classifier**
  - [ ] Implement `src/guardrails/injection_filter.py`.
  - [ ] Integrate transformer-based classifier / Lakera Guard heuristic checks.
  - [ ] Implement quarantine wrapper for suspicious log inputs (`<untrusted_payload>`).
  - [ ] Test with known prompt injection benchmarks (JailbreakBench / sample injection payloads).

- [ ] **5.2 Layer 2: Presidio PII & Credential Sanitizer**
  - [ ] Implement `src/guardrails/presidio_sanitizer.py`.
  - [ ] Configure recognizers for API keys, JWTs, AWS credentials, private IPs, SSNs, and emails.
  - [ ] Implement reversible cryptographic token vault for safe re-hydration.
  - [ ] Test redaction and re-hydration fidelity.

- [ ] **5.3 Layer 3: AST Tool Argument Validator**
  - [ ] Implement `src/guardrails/ast_tool_validator.py`.
  - [ ] Build Python AST visitor to inspect shell commands and script arguments.
  - [ ] Block dangerous system commands (`rm -rf`, unbound loops, privilege escalations, raw sockets).
  - [ ] Test AST rejection of prohibited execution patterns.

- [ ] **5.4 Layer 4: Output Faithfulness & Hallucination Guardrail**
  - [ ] Implement `src/guardrails/nli_faithfulness.py`.
  - [ ] Build Natural Language Inference (NLI) scoring against retrieved RAG grounding text.
  - [ ] Reject or flag remediation steps not directly corroborated by knowledge sources.

---

## Phase 6: LangGraph Multi-Agent Orchestration

- [ ] **6.1 Graph State Definition**
  - [ ] Implement `src/agents/state.py` defining `IncidentState` (TypedDict & Pydantic models).
  - [ ] Add state reducers for evidence list appending and audit logs.

- [ ] **6.2 Specialist Nodes**
  - [ ] Implement `src/agents/nodes/triage_node.py` (MITRE ATT&CK mapping, severity calculation).
  - [ ] Implement `src/agents/nodes/forensics_node.py` (evidence collection planning).
  - [ ] Implement `src/agents/nodes/threat_intel_node.py` (queries RAG subsystem).
  - [ ] Implement `src/agents/nodes/remediation_node.py` (synthesizes containment actions).
  - [ ] Implement `src/agents/nodes/critic_node.py` (validates evidence vs. conclusion; triggers reflection).

- [ ] **6.3 Supervisor & Graph Routing**
  - [ ] Implement `src/agents/supervisor.py` managing node transitions and completion criteria.
  - [ ] Build `src/agents/graph.py` assembling the `StateGraph`.

- [ ] **6.4 Human-in-the-Loop (HITL) Checkpoints & Redis Persistence**
  - [ ] Connect `AsyncRedisSaver` checkpointer to `StateGraph`.
  - [ ] Configure `interrupt_before=["remediation_executor"]`.
  - [ ] Implement state pause, human decision resume, and state modification API integration.
  - [ ] Write integration test verifying graph pauses at checkpoint and resumes upon approval.

---

## Phase 7: Sandboxed Tool Execution Environment

- [ ] **7.1 Docker Sandboxed Runner**
  - [ ] Implement `src/sandbox/docker_runner.py` using Docker Engine API.
  - [ ] Configure container profile:
    - [ ] Read-only root filesystem (`--read-only`).
    - [ ] Dropped capabilities (`--cap-drop=ALL`).
    - [ ] No new privileges (`--security-opt=no-new-privileges:true`).
    - [ ] CPU / RAM quotas (0.5 vCPU, 512MB RAM).
    - [ ] Zero external network access (`--network=none`).
  - [ ] Mount target log files/artifacts as read-only volumes.

- [ ] **7.2 Forensic Tool Integrations**
  - [ ] Implement Yara rule scanning tool in sandbox.
  - [ ] Implement log parser and regex IoC extraction tool in sandbox.
  - [ ] Write integration test verifying malicious execution escape attempts fail.

---

## Phase 8: Observability, Evals Harness & CI/CD

- [ ] **8.1 OpenTelemetry & Phoenix Tracing**
  - [ ] Implement `src/telemetry/otel_config.py`.
  - [ ] Instrument gRPC server, FastAPI routes, RabbitMQ workers, and LangGraph spans.
  - [ ] Connect traces and spans to self-hosted Arize Phoenix dashboard.

- [ ] **8.2 Automated Evaluation Suite (DeepEval)**
  - [ ] Create evaluation dataset `tests/evals/datasets/incidents_eval.json`.
  - [ ] Implement `tests/evals/test_agent_evals.py`:
    - [ ] Evaluate *Faithfulness Metric* on agent reports.
    - [ ] Evaluate *Answer Relevancy Metric*.
    - [ ] Evaluate *Context Precision* and *Context Recall* on RAG engine.
    - [ ] Evaluate *Adversarial Robustness* against injection attacks.

- [ ] **8.3 GitHub Actions CI/CD Pipeline**
  - [ ] Author `.github/workflows/ci.yml` running linting, unit tests, and integration tests.
  - [ ] Author `.github/workflows/evals.yml` running DeepEval benchmarks with failure thresholds.

---

## Phase 9: End-to-End Simulation & Verification

- [ ] **9.1 Simulated Incident Scenarios**
  - [ ] Implement `scripts/simulate_attack.py` simulating:
    - [ ] Scenario A: Brute force SSH intrusion with prompt injection in User-Agent header.
    - [ ] Scenario B: Ransomware staging with suspicious PowerShell execution.
    - [ ] Scenario C: Exfiltration attempt with malicious outbound IP.
- [ ] **9.2 Full System Walkthrough**
  - [ ] Stream simulated events via gRPC client.
  - [ ] Verify input prompt injection quarantine and PII redaction.
  - [ ] Verify RabbitMQ queue consumption and LangGraph multi-agent triage.
  - [ ] Verify Qdrant hybrid RAG retrieval of MITRE ATT&CK mitigation playbooks.
  - [ ] Verify graph pauses at Human-in-the-Loop checkpoint.
  - [ ] Submit analyst approval via REST API.
  - [ ] Verify AST validation and sandboxed Docker remediation execution.
  - [ ] Verify Phoenix trace generation and DeepEval passing score.
