# AutoSOC: Production-Grade Autonomous Cyber Incident Response & SOC Co-Pilot

AutoSOC is an industry-level, production-grade autonomous Security Operations Center (SOC) co-pilot and incident response system. It ingests high-throughput security telemetry over **gRPC**, manages asynchronous task queues with **RabbitMQ**, persists state and semantic caches with **Redis**, orchestrates a multi-agent team via **LangGraph**, grounds analysis with **Advanced Hybrid RAG**, defends against adversarial attacks with a **Multi-Tier Guardrail Matrix**, executes forensic actions in an **isolated Docker sandbox**, and guarantees quality via **DeepEval & OpenTelemetry/Phoenix**.

---

## Key Architectural Pillars

* **Stateful Multi-Agent Orchestration (LangGraph):** Hierarchical Supervisor architecture with specialized agents (Triage, Forensics, Threat Intel, Remediation Planner, and Critic) featuring Human-in-the-Loop (HITL) checkpoints.
* **Advanced Hybrid RAG & Self-RAG:** Qdrant-backed hybrid retrieval (Dense + Sparse BM25), Reciprocal Rank Fusion (RRF), Cross-Encoder re-ranking, and Corrective RAG (CRAG) query reformulation.
* **Zero-Trust Multi-Tier Guardrails:**
  * Ingress model-based prompt injection detection (Lakera / DeBERTa).
  * PII & secret token anonymization (Microsoft Presidio) with a cryptographic reversible vault.
  * AST-based tool argument sanitizer.
  * Natural Language Inference (NLI) faithfulness and hallucination defense.
* **Dual-Protocol Interfaces:**
  * High-performance, streaming telemetry ingestion via **gRPC (Protobuf) with mTLS**.
  * Full-featured **REST API (FastAPI)** with OAuth2/JWT, OpenAPI schemas, and webhook support.
* **Distributed Asynchronous Event Backbone:**
  * **RabbitMQ** with dead-letter queues (DLQ), consumer groups, and backpressure.
  * **Redis Cluster** for semantic caching (vector cosine similarity), sliding-window rate limiting, distributed locking (`Redlock`), and LangGraph checkpointer persistence.
* **Isolated Sandbox Tool Execution:** Ephemeral, rootless Docker/gVisor micro-containers with dropped Linux capabilities and zero network egress for forensic script execution.
* **Enterprise Observability & Continuous Evals:** OpenTelemetry distributed tracing, self-hosted Arize Phoenix / LangSmith, and automated regression testing via DeepEval.

---

## Project Documentation Index

Detailed architectural blueprints and execution roadmaps have been generated in this directory:

1. [ARCHITECTURE.md](file:///home/viper/Desktop/auto-soc/ARCHITECTURE.md) — Comprehensive technical specification, component deep dives, data flow diagrams, and directory layouts.
2. [CHECKLIST.md](file:///home/viper/Desktop/auto-soc/CHECKLIST.md) — Step-by-step master implementation checklist tracking every milestone from environment setup to end-to-end attack simulation.

---

## High-Level Repository Layout

```text
auto-soc/
├── README.md               # High-level overview & quick reference
├── ARCHITECTURE.md         # Full technical specification & architecture
├── CHECKLIST.md            # Step-by-step implementation checklist
├── docker-compose.yml      # Local infrastructure (Qdrant, Redis, RabbitMQ, Phoenix)
├── pyproject.toml          # Monorepo dependencies and tool configurations
├── protos/                 # Protocol Buffers definitions (.proto)
│   └── telemetry.proto
├── src/
│   ├── api/                # FastAPI REST Gateway & gRPC Server endpoints
│   ├── agents/             # LangGraph StateGraph, Supervisor & Specialist nodes
│   ├── rag/                # Ingestion, Hybrid Search (Dense+BM25), RRF, Reranker
│   ├── guardrails/         # Input, Tool AST, and Output NLI Guardrails
│   ├── queue/              # RabbitMQ consumers, producers, and Celery tasks
│   ├── cache/              # Redis Semantic Cache, Checkpointer & Redlock
│   ├── sandbox/            # Docker container isolation & forensic execution
│   └── telemetry/          # OpenTelemetry instrumentation & Phoenix tracing
└── tests/
    ├── unit/               # Unit test suites
    ├── integration/        # Integration tests across services
    └── evals/              # DeepEval LLM evaluation harness & benchmarks
```
