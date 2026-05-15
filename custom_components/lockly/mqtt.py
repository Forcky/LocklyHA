"""Lockly MQTT manager — real-time lock state via Lockly Paho broker."""
from __future__ import annotations

import json
import logging
import ssl
import uuid

import paho.mqtt.client as paho
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

_BROKER = "mqttuswest02-lb-001-b5ed8c5e37b3a497.elb.us-west-2.amazonaws.com"
_PORT = 8883
_TOPIC = "server"


class LocklyMQTTManager:
    """Connect to the Lockly Paho MQTT broker and update coordinator on DEVICE_STATE messages.

    Auth: JWT bearer token as MQTT password; username = account email.
    Falls back to polling-only mode if MQTT connection is refused (rc != 0).
    """

    def __init__(self, hass: HomeAssistant, coordinator) -> None:
        self._hass = hass
        self._coordinator = coordinator
        self._client: paho.Client | None = None

    async def async_start(self) -> None:
        jwt = self._coordinator.jwt
        email = self._coordinator.email
        # Unique client ID per integration instance; reuse avoids duplicate-session kicks.
        client_id = str(uuid.uuid4()).replace("-", "")

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                _LOGGER.info("Lockly MQTT connected")
                client.subscribe(_TOPIC, qos=0)
            else:
                _LOGGER.warning(
                    "Lockly MQTT connection refused rc=%s — "
                    "real-time push disabled, polling continues",
                    rc,
                )

        def on_disconnect(client, userdata, rc):
            if rc != 0:
                _LOGGER.warning("Lockly MQTT disconnected unexpectedly rc=%s", rc)

        def on_message(client, userdata, msg):
            try:
                data = json.loads(msg.payload.decode())
                _LOGGER.debug(
                    "Lockly MQTT raw: topic=%s payload=%s",
                    msg.topic,
                    msg.payload[:400].decode(errors="replace"),
                )
                name = (data.get("header") or {}).get("name")
                if name == "deviceStateCallback":
                    self._hass.loop.call_soon_threadsafe(
                        self._hass.async_create_task,
                        self._process_device_state(data),
                    )
            except Exception:
                _LOGGER.exception("Lockly MQTT message parse error")

        cli = paho.Client(client_id=client_id, protocol=paho.MQTTv311)
        cli.username_pw_set(email, jwt)
        # Lockly's broker presents a self-signed chain; skip verification.
        cli.tls_set(cert_reqs=ssl.CERT_NONE)
        cli.tls_insecure_set(True)
        cli.on_connect = on_connect
        cli.on_disconnect = on_disconnect
        cli.on_message = on_message
        self._client = cli

        try:
            await self._hass.async_add_executor_job(
                lambda: cli.connect(_BROKER, _PORT, keepalive=60)
            )
            await self._hass.async_add_executor_job(cli.loop_start)
        except Exception:
            _LOGGER.exception("Lockly MQTT failed to connect — polling-only mode")

    async def _process_device_state(self, data: dict) -> None:
        items = data.get("items") or []
        for item in items:
            device_id = (item.get("deviceId") or "").lower()
            raw_states = item.get("states") or []
            states = {s["statusKey"]: s["statusValue"] for s in raw_states if "statusKey" in s}
            _LOGGER.debug("DEVICE_STATE lock=%s states=%s", device_id, states)

            if not self._coordinator.data or device_id not in self._coordinator.data:
                _LOGGER.debug("DEVICE_STATE: unknown lock %s — ignoring", device_id)
                continue

            update: dict = {}
            if "LOCKED_STATUS" in states:
                update["is_locked"] = states["LOCKED_STATUS"] == "1"
            if "MAGNET" in states:
                update["door_sensor_open"] = states["MAGNET"] == "1"

            if update:
                updated_data = {
                    **self._coordinator.data,
                    device_id: {**self._coordinator.data[device_id], **update},
                }
                self._coordinator.async_set_updated_data(updated_data)

    async def async_stop(self) -> None:
        if self._client:
            try:
                await self._hass.async_add_executor_job(self._client.loop_stop)
                await self._hass.async_add_executor_job(self._client.disconnect)
            except Exception:
                _LOGGER.debug("Lockly MQTT stop error (ignored)")
            self._client = None
