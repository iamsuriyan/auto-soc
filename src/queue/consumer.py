"""
src/queue/consumer.py
======================
Asynchronous RabbitMQ Consumer Worker Pool.
Enforces:
  - Backpressure via prefetch_count (default: 10)
  - Automatic JSON parsing
  - Per-message acknowledgment (ACK)
  - Dead-Letter Queue (DLQ) rejection (NACK without requeue) after max retries
"""

import asyncio
import json
from typing import Awaitable, Callable, Dict, Optional
import aio_pika
from aio_pika.abc import AbstractIncomingMessage, AbstractQueue

from src.logger import get_logger
from src.queue.rabbitmq_client import RabbitMQClient, rabbitmq_client

logger = get_logger(__name__)


class EventConsumer:
    """
    Subscribes to a durable RabbitMQ queue with backpressure and dead-letter protection.
    """

    def __init__(
        self,
        queue_name: str,
        handler: Callable[[Dict], Awaitable[None]],
        prefetch_count: int = 10,
        max_retries: int = 3,
        client: Optional[RabbitMQClient] = None
    ):
        self.queue_name = queue_name
        self.handler = handler
        self.prefetch_count = prefetch_count
        self.max_retries = max_retries
        self.client = client or rabbitmq_client
        self._consumer_tag: Optional[str] = None
        self._queue: Optional[AbstractQueue] = None
        # Track delivery attempts per message ID
        self._retry_tracker: dict[str, int] = {}

    async def _process_message(self, message: AbstractIncomingMessage) -> None:
        """
        Processes a single message wrapped in an atomic ACK/NACK context.
        """
        async with message.process(requeue=False, ignore_processed=True):
            msg_id = message.message_id or "unknown"
            current_attempts = self._retry_tracker.get(msg_id, 0)

            try:
                # 1. Parse payload
                payload = json.loads(message.body.decode("utf-8"))
                logger.info(
                    "consumer_processing_started",
                    queue=self.queue_name,
                    msg_id=msg_id,
                    attempt=current_attempts + 1
                )

                # 2. Invoke the specialist agent handler
                await self.handler(payload)

                # 3. Clean up retry tracker on success
                self._retry_tracker.pop(msg_id, None)

                logger.info(
                    "consumer_processing_succeeded",
                    queue=self.queue_name,
                    msg_id=msg_id
                )

            except Exception as exc:
                logger.error(
                    "consumer_processing_failed",
                    queue=self.queue_name,
                    msg_id=msg_id,
                    error=str(exc),
                    attempt=current_attempts + 1
                )

                if current_attempts < self.max_retries:
                    self._retry_tracker[msg_id] = current_attempts + 1
                    # NACK with requeue=True to retry
                    await message.nack(requeue=True)
                else:
                    # Clean up tracker and reject without requeue -> Routes to Dead-Letter Queue
                    self._retry_tracker.pop(msg_id, None)
                    logger.warning(
                        "consumer_message_diverted_to_dlq",
                        queue=self.queue_name,
                        msg_id=msg_id,
                        reason="max_retries_exceeded"
                    )
                    await message.nack(requeue=False)

    async def start(self) -> None:
        """Connects, applies backpressure prefetch limit, and begins consuming."""
        channel = await self.client.get_channel(prefetch_count=self.prefetch_count)
        self._queue = await channel.get_queue(self.queue_name)
        self._consumer_tag = await self._queue.consume(self._process_message)
        logger.info(
            "consumer_started",
            queue=self.queue_name,
            prefetch=self.prefetch_count,
            consumer_tag=self._consumer_tag
        )

    async def stop(self) -> None:
        """Cancels consumer subscription."""
        if self._queue and self._consumer_tag:
            await self._queue.cancel(self._consumer_tag)
            logger.info("consumer_stopped", queue=self.queue_name)
