"""
src/queue/rabbitmq_client.py
=============================
Asynchronous RabbitMQ connection manager and topology declarator using aio-pika.
Declares:
  - Topic Exchange: `soc.events` (for main alert routing)
  - Dead-Letter Exchange: `soc.dlx` (for poisoned/malformed payloads)
  - Queues with Dead-Letter bindings:
      * `alerts.raw` -> bound to `alert.raw.#`
      * `alerts.triage` -> bound to `alert.triage.#`
      * `remediation.approval` -> bound to `remediation.approval.#`
      * `alerts.dead_letter` -> bound to `soc.dlx`
"""

import asyncio
from typing import Optional
import aio_pika
from aio_pika.abc import (
    AbstractChannel,
    AbstractConnection,
    AbstractExchange,
    AbstractQueue,
    ExchangeType,
)
from src.logger import get_logger
from src.config import settings

logger = get_logger(__name__)

# Core Topology Names
EXCHANGE_EVENTS = "soc.events"
EXCHANGE_DLX = "soc.dlx"

QUEUE_ALERTS_RAW = "alerts.raw"
QUEUE_ALERTS_TRIAGE = "alerts.triage"
QUEUE_REMEDIATION_APPROVAL = "remediation.approval"
QUEUE_DEAD_LETTER = "alerts.dead_letter"

ROUTING_KEY_RAW = "alert.raw.#"
ROUTING_KEY_TRIAGE = "alert.triage.#"
ROUTING_KEY_APPROVAL = "remediation.approval.#"


class RabbitMQClient:
    """
    Robust asynchronous RabbitMQ client.
    Handles auto-reconnect, topology declaration, and channel management.
    """

    def __init__(self, amqp_url: Optional[str] = None):
        self.amqp_url = amqp_url or settings.rabbitmq_url
        self._connection: Optional[AbstractConnection] = None
        self._channel: Optional[AbstractChannel] = None
        self.events_exchange: Optional[AbstractExchange] = None
        self.dlx_exchange: Optional[AbstractExchange] = None
        self.queues: dict[str, AbstractQueue] = {}

    async def connect(self) -> AbstractConnection:
        """Establishes robust connection with automatic reconnection on failure."""
        if not self._connection or self._connection.is_closed:
            logger.info("rabbitmq_connecting", url=self.amqp_url.split("@")[-1])
            self._connection = await aio_pika.connect_robust(self.amqp_url)
            self._channel = await self._connection.channel()
            logger.info("rabbitmq_connected")
        return self._connection

    async def get_channel(self, prefetch_count: int = 10) -> AbstractChannel:
        """Returns channel with backpressure prefetch limits applied."""
        conn = await self.connect()
        channel = await conn.channel()
        await channel.set_qos(prefetch_count=prefetch_count)
        return channel

    async def declare_topology(self) -> None:
        """
        Idempotently declares all exchanges, queues, and dead-letter routing bindings.
        """
        await self.connect()
        channel = self._channel

        # 1. Declare Dead-Letter Exchange (Fanout so all dead letters reach the DLQ)
        self.dlx_exchange = await channel.declare_exchange(
            EXCHANGE_DLX,
            ExchangeType.FANOUT,
            durable=True
        )

        # 2. Declare Dead-Letter Queue and bind to DLX
        dlq = await channel.declare_queue(
            QUEUE_DEAD_LETTER,
            durable=True
        )
        await dlq.bind(self.dlx_exchange)
        self.queues[QUEUE_DEAD_LETTER] = dlq

        # 3. Declare Main Events Topic Exchange
        self.events_exchange = await channel.declare_exchange(
            EXCHANGE_EVENTS,
            ExchangeType.TOPIC,
            durable=True
        )

        # Standard Queue Arguments: Dead-Letter Exchange + Priority Queuing (0-9)
        queue_args = {
            "x-dead-letter-exchange": EXCHANGE_DLX,
            "x-dead-letter-routing-key": "dead.letter",
            "x-max-priority": 10
        }

        # 4. Declare & Bind alerts.raw queue
        raw_queue = await channel.declare_queue(
            QUEUE_ALERTS_RAW,
            durable=True,
            arguments=queue_args
        )
        await raw_queue.bind(self.events_exchange, routing_key=ROUTING_KEY_RAW)
        self.queues[QUEUE_ALERTS_RAW] = raw_queue

        # 5. Declare & Bind alerts.triage queue
        triage_queue = await channel.declare_queue(
            QUEUE_ALERTS_TRIAGE,
            durable=True,
            arguments=queue_args
        )
        await triage_queue.bind(self.events_exchange, routing_key=ROUTING_KEY_TRIAGE)
        self.queues[QUEUE_ALERTS_TRIAGE] = triage_queue

        # 6. Declare & Bind remediation.approval queue
        approval_queue = await channel.declare_queue(
            QUEUE_REMEDIATION_APPROVAL,
            durable=True,
            arguments=queue_args
        )
        await approval_queue.bind(self.events_exchange, routing_key=ROUTING_KEY_APPROVAL)
        self.queues[QUEUE_REMEDIATION_APPROVAL] = approval_queue

        logger.info(
            "rabbitmq_topology_declared",
            exchanges=[EXCHANGE_EVENTS, EXCHANGE_DLX],
            queues=list(self.queues.keys())
        )

    async def close(self) -> None:
        """Gracefully closes open channels and connections."""
        if self._channel and not self._channel.is_closed:
            await self._channel.close()
        if self._connection and not self._connection.is_closed:
            await self._connection.close()
        logger.info("rabbitmq_connection_closed")


# Module-level singleton
rabbitmq_client = RabbitMQClient()
