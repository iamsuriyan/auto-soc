#!/usr/bin/env bash
# ==============================================================================
#  generate_protos.sh — Compile Protocol Buffers into Python Stubs
# ==============================================================================

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

OUT_DIR="src/api/grpc/generated"
mkdir -p "$OUT_DIR"

echo "⚙️  Compiling .proto definitions to Python..."

# Run protoc compiler using python module
.venv/bin/python -m grpc_tools.protoc \
    -Iprotos \
    --python_out="$OUT_DIR" \
    --grpc_python_out="$OUT_DIR" \
    protos/telemetry.proto protos/incident.proto

# Ensure package initialization
touch "$OUT_DIR/__init__.py"

# Fix protoc's known Python 3 relative import bug in generated *_grpc.py files
sed -i 's/import telemetry_pb2/from . import telemetry_pb2/g' "$OUT_DIR/telemetry_pb2_grpc.py"
sed -i 's/import incident_pb2/from . import incident_pb2/g' "$OUT_DIR/incident_pb2_grpc.py"

echo "✅ Protobuf stubs successfully generated in $OUT_DIR"
