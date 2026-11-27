"""
src/queue/publisher.py
=======================
Asynchronous RabbitMQ Message Publisher.
Provides durable publishing with JSON serialization, message IDs,
and delivery confirmation guarantees.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional, Union
import uuid
import aio_pika
from pydantic import BaseModel

from src.logger import get_logger
from src.queue.rabbitmq_client import EXCHANGE_EVENTS, RabbitMQClient, rabbitmq_client

logger = get_logger(__name__)


class EventPublisher:
    """
    Publishes strongly-typed security messages to the RabbitMQ events topic exchange.
    """

    def __init__(self, client: Optional[RabbitMQClient] = None):
        self.client = client or rabbitmq_client

    async def publish(
        self,
        routing_key: str,
        payload: Union[Dict[str, Any], BaseModel],
        headers: Optional[Dict[str, Any]] = None,
        priority: int = 0
    ) -> str:
        """
        Publishes a message to `soc.events` with delivery confirmation.

        :param routing_key: Topic routing string (e.g. "alert.raw.edr", "alert.triage.critical")
        :param payload: Dict or Pydantic model to be JSON-serialized
        :param headers: Optional metadata headers (tracing, retry counters)
        :param priority: AMQP priority (0 to 9, where 9 is highest)
        :return: Published message UUID
        """
        await self.client.connect()
        channel = await self.client.get_channel()

        # Extract dict from Pydantic model if applicable
        if isinstance(payload, BaseModel):
            data = payload.model_dump()
        else:
            data = payload

        message_id = f"msg-{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        body_bytes = json.dumps(data).encode("utf-8")

        msg_headers = {
            "timestamp": now_iso,
            "x-retry-count": 0,
            **(headers or {})
        }

        # Durable, persistent message (delivery_mode=PERSISTENT writes to disk)
        message = aio_pika.Message(
            body=body_bytes,
            content_type="application/json",
            content_encoding="utf-8",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            message_id=message_id,
            priority=priority,
            headers=msg_headers
        )

        exchange = await channel.get_exchange(EXCHANGE_EVENTS)
        await exchange.publish(message, routing_key=routing_key)

        logger.info(
            "message_published",
            message_id=message_id,
            routing_key=routing_key,
            payload_size=len(body_bytes)
        )

        return message_id
