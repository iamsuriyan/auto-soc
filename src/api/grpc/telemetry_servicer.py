"""
src/api/grpc/telemetry_servicer.py
===================================
Implementation of the gRPC TelemetryIngestService.
Handles high-throughput asynchronous streams of AlertEvent protobuf messages
from distributed EDR sensors and syslog forwarders.
"""

from typing import AsyncIterator, Callable, List, Optional
import uuid

from src.logger import bind_context, clear_context, get_logger
from src.api.grpc.generated import telemetry_pb2, telemetry_pb2_grpc

logger = get_logger(__name__)


class TelemetryServicer(telemetry_pb2_grpc.TelemetryIngestServiceServicer):
    """
    gRPC Servicer that handles continuous streams of raw security telemetry.
    """

    def __init__(self, on_alert_received: Optional[Callable] = None):
        """
        :param on_alert_received: Optional async callback hook triggered on each valid alert
                                  (used later to forward events into RabbitMQ / LangGraph).
        """
        self.on_alert_received = on_alert_received
        # In-memory buffer for tracking alerts in current session
        self.received_alerts: List[telemetry_pb2.AlertEvent] = []

    async def StreamAlerts(
        self,
        request_iterator: AsyncIterator[telemetry_pb2.AlertEvent],
        context
    ) -> telemetry_pb2.IngestSummary:
        """
        Client-streaming RPC:
        Sensors stream multiple AlertEvents over a single HTTP/2 connection.
        The server validates, buffers, and returns an IngestSummary batch receipt.
        """
        batch_id = f"batch-{uuid.uuid4().hex[:10]}"
        bind_context(batch_id=batch_id)
        processed_count = 0
        rejected_count = 0

        logger.info("grpc_stream_alerts_started")

        try:
            async for alert in request_iterator:
                # Basic wire-level validation
                if not alert.event_id or not alert.source_ip:
                    rejected_count += 1
                    logger.warning(
                        "grpc_alert_rejected_malformed",
                        event_id=alert.event_id,
                        reason="missing_event_id_or_source_ip"
                    )
                    continue

                # Buffer alert
                self.received_alerts.append(alert)
                processed_count += 1

                # If callback hooked (e.g. forward to message queue), invoke it
                if self.on_alert_received:
                    try:
                        await self.on_alert_received(alert)
                    except Exception as e:
                        logger.error("grpc_alert_forward_failed", event_id=alert.event_id, error=str(e))

            status = "SUCCESS" if rejected_count == 0 else ("PARTIAL" if processed_count > 0 else "FAILED")

            logger.info(
                "grpc_stream_alerts_completed",
                batch_id=batch_id,
                processed=processed_count,
                rejected=rejected_count,
                status=status
            )

            return telemetry_pb2.IngestSummary(
                processed_count=processed_count,
                rejected_count=rejected_count,
                batch_id=batch_id,
                status=status
            )

        except Exception as e:
            logger.error("grpc_stream_alerts_unhandled_error", batch_id=batch_id, error=str(e))
            return telemetry_pb2.IngestSummary(
                processed_count=processed_count,
                rejected_count=rejected_count + 1,
                batch_id=batch_id,
                status="FAILED"
            )
