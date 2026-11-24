"""
tests/integration/test_grpc_streaming.py
=========================================
Integration test suite for gRPC Telemetry Ingestion Server.
Verifies:
  1. Client with valid mTLS certificate streams 100 alerts successfully.
  2. IngestSummary reflects processed/rejected counts accurately.
  3. Client without valid certificate is rejected at the TLS boundary.
"""

import time
import pytest
import grpc

from src.api.grpc.generated import telemetry_pb2, telemetry_pb2_grpc
from src.api.grpc.server import build_grpc_server, create_server_credentials
from src.api.grpc.telemetry_servicer import TelemetryServicer

TEST_PORT = 50055
BIND_ADDRESS = f"127.0.0.1:{TEST_PORT}"


@pytest.fixture
async def grpc_test_server():
    """
    Spins up an isolated mTLS gRPC server on TEST_PORT for each test.
    """
    servicer = TelemetryServicer()
    server = build_grpc_server(servicer=servicer)

    credentials = create_server_credentials(
        ca_cert_path="certs/ca.crt",
        server_cert_path="certs/server.crt",
        server_key_path="certs/server.key",
        require_client_auth=True
    )
    server.add_secure_port(BIND_ADDRESS, credentials)
    await server.start()

    yield servicer

    await server.stop(grace=1.0)


@pytest.mark.asyncio
async def test_stream_alerts_mtls_success(grpc_test_server):
    """
    Asserts an authorized EDR sensor with valid mTLS certificates
    can stream 100 security events and receive an IngestSummary receipt.
    """
    # Load CA and client certificate pair
    with open("certs/ca.crt", "rb") as f:
        root_ca = f.read()
    with open("certs/client.crt", "rb") as f:
        client_cert = f.read()
    with open("certs/client.key", "rb") as f:
        client_key = f.read()

    client_creds = grpc.ssl_channel_credentials(
        root_certificates=root_ca,
        private_key=client_key,
        certificate_chain=client_cert
    )

    # Note: override target authority so TLS hostname matches server cert CN (localhost)
    options = (("grpc.ssl_target_name_override", "localhost"),)

    async with grpc.aio.secure_channel(BIND_ADDRESS, client_creds, options=options) as channel:
        stub = telemetry_pb2_grpc.TelemetryIngestServiceStub(channel)

        # Stream generator producing 100 events
        async def generate_alerts():
            for i in range(100):
                yield telemetry_pb2.AlertEvent(
                    event_id=f"evt-test-{i:03d}",
                    source_ip="192.168.1.50",
                    destination_ip="10.0.0.12",
                    hostname="prod-finance-01",
                    event_type="PROCESS_INJECTION",
                    timestamp=int(time.time()),
                    raw_payload=f"Process powershell.exe injected code into svchost.exe (ID: {i})",
                    metadata={"pid": str(1000 + i), "user": "SYSTEM"}
                )

        summary = await stub.StreamAlerts(generate_alerts())

        assert summary.processed_count == 100
        assert summary.rejected_count == 0
        assert summary.status == "SUCCESS"
        assert summary.batch_id.startswith("batch-")
        assert len(grpc_test_server.received_alerts) == 100


@pytest.mark.asyncio
async def test_unauthenticated_client_rejected_by_mtls(grpc_test_server):
    """
    Asserts a client without a client certificate is rejected by the server (Zero-Trust).
    """
    with open("certs/ca.crt", "rb") as f:
        root_ca = f.read()

    # Client only provides CA to verify server, but provides NO client cert/key
    unauthenticated_creds = grpc.ssl_channel_credentials(root_certificates=root_ca)
    options = (("grpc.ssl_target_name_override", "localhost"),)

    async with grpc.aio.secure_channel(BIND_ADDRESS, unauthenticated_creds, options=options) as channel:
        stub = telemetry_pb2_grpc.TelemetryIngestServiceStub(channel)

        async def generate_single_alert():
            yield telemetry_pb2.AlertEvent(
                event_id="evt-unauthorized",
                source_ip="10.0.0.99",
                destination_ip="10.0.0.1",
                event_type="UNAUTHORIZED_SCAN"
            )

        # Must raise RpcError with UNAVAILABLE / Handshake Failure
        with pytest.raises(grpc.RpcError) as exc_info:
            await stub.StreamAlerts(generate_single_alert())

        assert exc_info.value.code() in (
            grpc.StatusCode.UNAVAILABLE,
            grpc.StatusCode.UNAUTHENTICATED,
            grpc.StatusCode.INTERNAL
        )
