"""
tests/integration/test_rabbitmq_backbone.py
============================================
Integration tests for the RabbitMQ Event Backbone.
Verifies:
  1. Topology declaration creates exchanges and queues with DLQ bindings.
  2. Publisher publishes to `soc.events`, routed to `alerts.raw`.
  3. Consumer receives, parses, and acknowledges message.
  4. Poisoned/failing messages are rejected after max retries and routed to Dead-Letter Queue (DLQ).
"""

import asyncio
import time
import pytest

from src.queue.consumer import EventConsumer
from src.queue.publisher import EventPublisher
from src.queue.rabbitmq_client import (
    EXCHANGE_EVENTS,
    QUEUE_ALERTS_RAW,
    QUEUE_DEAD_LETTER,
    RabbitMQClient,
)


@pytest.fixture(scope="function")
async def mq():
    """Initializes RabbitMQ client, recreating queues with updated arguments."""
    client = RabbitMQClient()
    await client.connect()

    # Delete queues to allow arg migration (e.g. x-max-priority)
    channel = await client.get_channel()
    for q_name in [QUEUE_ALERTS_RAW, QUEUE_DEAD_LETTER, "alerts.triage", "remediation.approval"]:
        try:
            q = await channel.get_queue(q_name)
            await q.delete()
        except Exception:
            pass

    # Declare fresh topology with priority + DLQ
    await client.declare_topology()

    yield client
    await client.close()


@pytest.mark.asyncio
async def test_topology_declaration(mq: RabbitMQClient):
    """Asserts all core queues and exchanges exist."""
    assert QUEUE_ALERTS_RAW in mq.queues
    assert QUEUE_DEAD_LETTER in mq.queues
    assert mq.events_exchange is not None
    assert mq.dlx_exchange is not None


@pytest.mark.asyncio
async def test_publish_and_consume_alert(mq: RabbitMQClient):
    """
    Asserts publishing an alert to `alert.raw.edr` routes to `alerts.raw`
    and the EventConsumer successfully processes and ACKs it.
    """
    received_events = []

    async def sample_agent_handler(payload: dict):
        received_events.append(payload)

    # Start consumer with prefetch=5
    consumer = EventConsumer(
        queue_name=QUEUE_ALERTS_RAW,
        handler=sample_agent_handler,
        prefetch_count=5,
        client=mq
    )
    await consumer.start()

    # Publish alert
    publisher = EventPublisher(client=mq)
    test_alert = {
        "event_id": f"evt-mq-{int(time.time())}",
        "source_ip": "203.0.113.42",
        "hostname": "workstation-hr-04",
        "event_type": "POWERSHELL_SUSPICIOUS_ENCODED",
        "payload": "powershell.exe -enc JABz...=="
    }

    msg_id = await publisher.publish(
        routing_key="alert.raw.edr",
        payload=test_alert
    )
    assert msg_id.startswith("msg-")

    # Wait for consumer processing
    for _ in range(20):
        if len(received_events) > 0:
            break
        await asyncio.sleep(0.1)

    await consumer.stop()

    assert len(received_events) == 1
    assert received_events[0]["event_id"] == test_alert["event_id"]
    assert received_events[0]["hostname"] == "workstation-hr-04"


@pytest.mark.asyncio
async def test_poisoned_message_routed_to_dlq(mq: RabbitMQClient):
    """
    Asserts that a message that repeatedly fails execution is rejected
    and automatically shunted by RabbitMQ to the Dead-Letter Queue (`alerts.dead_letter`).
    """
    async def crashing_handler(_payload: dict):
        raise ValueError("Simulated catastrophic crash / memory bomb in agent logic")

    # Consumer configured with max_retries=1
    consumer = EventConsumer(
        queue_name=QUEUE_ALERTS_RAW,
        handler=crashing_handler,
        max_retries=1,
        client=mq
    )
    await consumer.start()

    publisher = EventPublisher(client=mq)
    poison_id = f"poison-{int(time.time())}"
    await publisher.publish(
        routing_key="alert.raw.poison",
        payload={"event_id": poison_id, "malicious_bomb": "boom"}
    )

    # Allow time for initial fail + retry + DLQ diversion
    await asyncio.sleep(0.8)
    await consumer.stop()

    # Inspect Dead-Letter Queue
    channel = await mq.get_channel()
    dlq = await channel.get_queue(QUEUE_DEAD_LETTER)

    # Get message from DLQ
    dlq_message = await dlq.get(no_ack=False, timeout=2.0)
    assert dlq_message is not None
    await dlq_message.ack()

    import json
    dead_payload = json.loads(dlq_message.body.decode("utf-8"))
    assert dead_payload["event_id"] == poison_id


@pytest.mark.asyncio
async def test_priority_message_jumps_to_front_of_queue(mq: RabbitMQClient):
    """
    Demonstrates priority queue jumping:
    1. Publishes 3 low-priority routine alerts (priority=1).
    2. Publishes 1 critical ransomware alert (priority=9) LAST.
    3. Asserts the consumer receives the priority=9 alert FIRST!
    """
    publisher = EventPublisher(client=mq)
    received_order = []

    # 1. Publish 3 low-priority messages
    for i in range(1, 4):
        await publisher.publish(
            routing_key="alert.raw.bulk",
            payload={"event_id": f"low-priority-{i}", "severity": "LOW"},
            priority=1
        )

    # 2. Publish 1 high-priority message LAST
    await publisher.publish(
        routing_key="alert.raw.urgent",
        payload={"event_id": "emergency-ransomware", "severity": "CRITICAL"},
        priority=9
    )

    # 3. Pull messages one by one and record order
    channel = await mq.get_channel()
    queue = await channel.get_queue(QUEUE_ALERTS_RAW)

    for _ in range(4):
        msg = await queue.get(no_ack=False, timeout=2.0)
        await msg.ack()
        import json
        data = json.loads(msg.body.decode("utf-8"))
        received_order.append(data["event_id"])

    # 4. Assert priority 9 jumped ahead of all priority 1 messages
    assert received_order[0] == "emergency-ransomware", (
        f"Expected emergency alert first, but got: {received_order}"
    )
    assert received_order[1:] == ["low-priority-1", "low-priority-2", "low-priority-3"]
