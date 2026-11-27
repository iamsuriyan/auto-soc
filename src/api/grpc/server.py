"""
src/api/grpc/server.py
======================
Asynchronous gRPC Server for AutoSOC Telemetry Ingestion.
Supports both mutual TLS (mTLS) with client certificate verification
and insecure modes for local unit testing.
"""

import asyncio
from pathlib import Path
from typing import Optional
import grpc
from src.logger import get_logger
from src.config import settings
from src.api.grpc.generated import telemetry_pb2_grpc
from src.api.grpc.telemetry_servicer import TelemetryServicer

logger = get_logger(__name__)


def create_server_credentials(
    ca_cert_path: str,
    server_cert_path: str,
    server_key_path: str,
    require_client_auth: bool = True
) -> grpc.ServerCredentials:
    """
    Builds SSL/TLS ServerCredentials enforcing mTLS client certificate verification.
    """
    with open(ca_cert_path, "rb") as f:
        root_ca_bytes = f.read()
    with open(server_cert_path, "rb") as f:
        server_cert_bytes = f.read()
    with open(server_key_path, "rb") as f:
        server_key_bytes = f.read()

    credentials = grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(server_key_bytes, server_cert_bytes)],
        root_certificates=root_ca_bytes,
        require_client_auth=require_client_auth
    )
    return credentials


def build_grpc_server(
    servicer: Optional[TelemetryServicer] = None,
    use_tls: bool = True,
    ca_cert_path: Optional[str] = None,
    server_cert_path: Optional[str] = None,
    server_key_path: Optional[str] = None,
) -> grpc.aio.Server:
    """
    Assembles the async gRPC server instance with registered servicers.
    """
    # Create asynchronous gRPC server
    server = grpc.aio.server()

    # Register Telemetry Ingestion Servicer
    telemetry_servicer = servicer or TelemetryServicer()
    telemetry_pb2_grpc.add_TelemetryIngestServiceServicer_to_server(telemetry_servicer, server)

    return server


async def start_grpc_server(
    host: Optional[str] = None,
    port: Optional[int] = None,
    use_tls: bool = True
) -> grpc.aio.Server:
    """
    Starts the gRPC server and begins listening for incoming telemetry connections.
    """
    host = host or settings.grpc_host
    port = port or settings.grpc_port
    bind_address = f"{host}:{port}"

    server = build_grpc_server(use_tls=use_tls)

    if use_tls:
        ca_path = settings.grpc_ca_cert_path
        cert_path = settings.grpc_tls_cert_path
        key_path = settings.grpc_tls_key_path

        # Verify certs exist
        if not (Path(ca_path).exists() and Path(cert_path).exists() and Path(key_path).exists()):
            raise FileNotFoundError(
                f"Missing TLS certificates for mTLS. Run `scripts/generate_certs.sh` first. "
                f"Paths: ca={ca_path}, cert={cert_path}, key={key_path}"
            )

        credentials = create_server_credentials(ca_path, cert_path, key_path, require_client_auth=True)
        server.add_secure_port(bind_address, credentials)
        logger.info("grpc_server_started_mtls", bind_address=bind_address)
    else:
        server.add_insecure_port(bind_address)
        logger.warning("grpc_server_started_insecure", bind_address=bind_address)

    await server.start()
    return server


if __name__ == "__main__":
    async def main():
        server = await start_grpc_server(use_tls=True)
        try:
            await server.wait_for_termination()
        except asyncio.CancelledError:
            await server.stop(grace=5.0)

    asyncio.run(main())
