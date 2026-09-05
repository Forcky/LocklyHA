"""Lockly MQTT manager — real-time lock state via Lockly Paho broker."""
from __future__ import annotations

import asyncio
import base64
import json
import time
import logging
import ssl
import uuid
from pathlib import Path

import paho.mqtt.client as paho
from homeassistant.core import HomeAssistant

from .api import mask_email

_LOGGER = logging.getLogger(__name__)

_BROKER = "mqttuswest02-lb-001-b5ed8c5e37b3a497.elb.us-west-2.amazonaws.com"
_PORT = 8883
# Publish only. The app posts commands here and never subscribes to it:
# Connection.java has publish() and messageArrived() and no subscribe() at all.
# This integration subscribed to it for a long time and the broker refused every
# time, correctly, because it is not a topic clients read from.
_PUBLISH_TOPIC = "server"

# Where the broker delivers replies and state callbacks: the client's own topic,
# derived from the MQTT client id. Verified empirically — a published command was
# answered on `client/<client_id>` with no SUBSCRIBE having been issued, so the
# broker holds a server-side subscription for it. We subscribe anyway, because a
# granted subscription is the documented way to receive and costs nothing if the
# broker is already pushing.
_CLIENT_TOPIC_PREFIX = "client/"

# Give up after this many non-permanent refusals rather than reconnecting forever.
_MAX_REFUSALS = 3

# How long to wait for the lock to answer a frame relayed over the broker.
# Observed round trips are under two seconds; this allows for a sleeping lock.
_RESPONSE_TIMEOUT = 20.0

# Client-certificate material for the broker, taken from res/raw of the Lockly
# app (3.2.9): R.raw.ca, R.raw.client and R.raw.client_key, the three files
# MqttSSLSocketFactory loads.  They are shipped in every copy of the app, so
# they are not a secret — but they do identify a Lockly client, and Lockly could
# rotate them, in which case push stops until these are refreshed.
_CERT_DIR = Path(__file__).parent / "certs"
_CA_CERT = _CERT_DIR / "ca.crt"
_CLIENT_CERT = _CERT_DIR / "client.crt"
_CLIENT_KEY = _CERT_DIR / "client_key.key"


class LocklyMQTTManager:
    """Connect to the Lockly Paho MQTT broker and update coordinator on DEVICE_STATE messages.

    Auth: JWT bearer token as MQTT password; username = account email.
    Falls back to polling-only mode if MQTT connection is refused (rc != 0).
    """

    def __init__(self, hass: HomeAssistant, coordinator) -> None:
        self._hass = hass
        self._coordinator = coordinator
        self._client: paho.Client | None = None
        self._connected = False
        self._refusals = 0
        self._gave_up = False
        self._client_id: str | None = None
        # requestId -> future awaiting that exchange's lockCommandResponse.
        self._pending: dict[str, asyncio.Future] = {}

    @property
    def connected(self) -> bool:
        """True once the broker has accepted the connection."""
        return self._connected

    def _give_up(self) -> None:
        """Stop paho's reconnect loop after an unrecoverable refusal.

        Called from a paho callback thread, so this must not touch the event
        loop — loop_stop() and disconnect() are both safe from there.
        """
        self._gave_up = True
        client = self._client
        if client is None:
            return
        try:
            client.loop_stop()
            client.disconnect()
        except Exception:  # noqa: BLE001 - teardown must not raise
            _LOGGER.debug("Lockly MQTT: error while stopping the client", exc_info=True)

    def _resolve(self, request_id: str | None, payload: dict) -> None:
        """Hand a reply to whoever is awaiting it.

        Called from the paho thread, so the future is resolved on the event loop
        rather than directly. The broker sends each reply more than once — every
        observed exchange arrived twice — so a second delivery for a future that
        is already done is dropped rather than raising InvalidStateError.
        """
        if not request_id:
            return
        future = self._pending.get(request_id)
        if future is None:
            return

        def _set() -> None:
            if not future.done():
                future.set_result(payload)

        self._hass.loop.call_soon_threadsafe(_set)

    async def async_start(self) -> None:
        jwt = self._coordinator.jwt
        email = self._coordinator.email

        missing = [p.name for p in (_CA_CERT, _CLIENT_CERT, _CLIENT_KEY) if not p.is_file()]
        if missing:
            _LOGGER.warning(
                "Lockly MQTT: missing client certificate file(s) %s in %s — the "
                "broker requires client-certificate auth, so push is disabled "
                "and state falls back to polling",
                ", ".join(missing), _CERT_DIR,
            )
            return
        # Unique client ID per integration instance; reuse avoids duplicate-session kicks.
        client_id = str(uuid.uuid4()).replace("-", "")
        self._client_id = client_id

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                self._connected = True
                # Logged at info: without it there is no way to tell a working
                # push connection from one that silently never connected.
                topic = _CLIENT_TOPIC_PREFIX + client_id
                _LOGGER.info("Lockly MQTT connected, subscribing to %r", topic)
                client.subscribe(topic, qos=0)
            else:
                self._connected = False
                # rc=5 is "not authorised": a credential problem, not a
                # transient one.  paho's network loop reconnects on its own, so
                # without stopping it here this becomes a connect-refuse-retry
                # storm against Lockly's broker several times a second, which
                # risks the account being throttled.
                self._refusals += 1
                permanent = rc == 5
                _LOGGER.warning(
                    "Lockly MQTT connection refused rc=%s%s — real-time push "
                    "disabled, polling continues",
                    rc,
                    " (not authorised; not retrying)" if permanent else "",
                )
                if permanent or self._refusals >= _MAX_REFUSALS:
                    self._give_up()

        def on_disconnect(client, userdata, rc):
            self._connected = False
            if rc != 0:
                _LOGGER.warning("Lockly MQTT disconnected unexpectedly rc=%s", rc)

        def on_subscribe(client, userdata, mid, granted_qos, properties=None):
            # A granted QoS of 0x80 is the MQTT "subscription failure" return
            # code, not a QoS level.  Reporting it as a confirmation hides the
            # fact that no messages will ever arrive.
            codes = list(granted_qos or [])
            topic = _CLIENT_TOPIC_PREFIX + client_id
            if any(int(c) == 0x80 for c in codes):
                # Not fatal any more. The broker was observed delivering a reply
                # on this topic without any subscription being granted, so a
                # refusal here does not mean nothing will arrive. Dropping the
                # session on it — which this used to do — would throw away a
                # connection that works.
                _LOGGER.info(
                    "Lockly MQTT: subscription to %r was refused (SUBACK 0x80), "
                    "keeping the connection: the broker pushes to this topic "
                    "regardless",
                    topic,
                )
            else:
                _LOGGER.info(
                    "Lockly MQTT subscribed to %r at qos=%s", topic, codes
                )

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
                elif name in ("lockCommandResponse", "exception"):
                    header = data.get("header") or {}
                    payload = data.get("payload") or {}
                    if name == "exception":
                        # The server reports delivery failures this way. Code
                        # 3005 "device is offline" means the hub is not on this
                        # channel, which is the difference between a working
                        # command path and a silent one.
                        _LOGGER.warning(
                            "Lockly MQTT: server returned an exception — code=%s %s",
                            payload.get("code"), payload.get("message"),
                        )
                        payload = {"code": payload.get("code") or -1,
                                   "errorMessage": payload.get("message")}
                    self._resolve(header.get("requestId"), payload)
            except Exception:
                _LOGGER.exception("Lockly MQTT message parse error")

        try:
            # Client construction sits inside the try: on paho-mqtt 2.x the v1
            # callback API must be requested explicitly, and an exception here
            # would otherwise propagate out and fail the whole config entry.
            try:
                cli = paho.Client(
                    callback_api_version=paho.CallbackAPIVersion.VERSION1,
                    client_id=client_id,
                    protocol=paho.MQTTv311,
                )
            except (AttributeError, TypeError):
                cli = paho.Client(client_id=client_id, protocol=paho.MQTTv311)  # paho 1.x

            # MqttConnectionOption.getUserName() returns
            # "{user_client_id}_{email}" when a server-assigned client id is
            # known, falling back to the bare email otherwise.  The broker
            # authorises subscriptions by that identity, so without the client
            # id it accepts the connection and then refuses the topic.
            server_client_id = getattr(self._coordinator, "mqtt_client_id", None)
            username = f"{server_client_id}_{email}" if server_client_id else email
            cli.username_pw_set(username, jwt)
            cli.on_connect = on_connect
            cli.on_disconnect = on_disconnect
            cli.on_subscribe = on_subscribe
            cli.on_message = on_message
            self._client = cli

            # The broker requires client-certificate authentication.  The app's
            # MqttSSLSocketFactory loads a CA, a client certificate and a client
            # private key into a KeyManagerFactory over TLSv1.2; connecting
            # without the client certificate is refused with rc=5, or accepted
            # and then denied at subscribe time with SUBACK 0x80.
            #
            # tls_set reads all three files from disk, so it must not run on the
            # event loop.  Hostname verification stays off: the broker is an AWS
            # ELB address and the certificate is issued by Lockly's own CA, so
            # the name will not match.  The chain itself is still verified
            # against that CA.
            await self._hass.async_add_executor_job(
                # tls_version is left at paho's default rather than pinned to
                # TLSv1.2 as the app does: that constant is deprecated, and the
                # default negotiates 1.2 with this broker anyway.
                lambda: cli.tls_set(
                    ca_certs=str(_CA_CERT),
                    certfile=str(_CLIENT_CERT),
                    keyfile=str(_CLIENT_KEY),
                    cert_reqs=ssl.CERT_REQUIRED,
                )
            )
            await self._hass.async_add_executor_job(cli.tls_insecure_set, True)
            # PgConfig's hardcoded address, not the one getHeartbeatTime
            # returns.  A network capture of the official app shows it
            # connecting to this host, and the API-reported address refuses
            # CONNECT outright with rc=5 where this one is accepted (and then
            # refuses the subscription, which is the real blocker).  Preferring
            # the API's address looked more correct and was strictly worse.
            # Host and port travel together: taking the port from a different
            # broker's config would be meaningless.
            host, port = _BROKER, _PORT
            api_host = getattr(self._coordinator, "mqtt_host", None)
            if api_host and api_host != host:
                _LOGGER.debug(
                    "Lockly MQTT: using PgConfig broker %s, not the address the "
                    "API reported (%s) — the app uses the former and the latter "
                    "refuses CONNECT",
                    host, api_host,
                )
            # The address is masked: this line is a routine paste into public
            # issues, and the diagnostic value is the client id and its
            # provenance, not who the account belongs to.
            log_username = (
                f"{server_client_id}_{mask_email(email)}"
                if server_client_id
                else mask_email(email)
            )
            _LOGGER.debug(
                "Lockly MQTT connecting to %s:%s as %s (client id %s)",
                host, port, log_username,
                "from API" if server_client_id else "generated",
            )
            await self._hass.async_add_executor_job(
                lambda: cli.connect(host, int(port), keepalive=60)
            )
            await self._hass.async_add_executor_job(cli.loop_start)
        except Exception:
            _LOGGER.exception("Lockly MQTT failed to connect — polling-only mode")

    async def async_reconnect(self) -> None:
        """Restart the MQTT session using the coordinator's current JWT.

        The broker password is the JWT, which the cloud rotates roughly every 24
        hours.  Without reconnecting, push dies silently at the first rotation.
        """
        await self.async_stop()
        await self.async_start()

    async def async_exchange_frame(
        self, device_id: str, frame_hex: str, timeout: float = _RESPONSE_TIMEOUT
    ) -> str | None:
        """Send a BLE frame over MQTT and return the lock's ACK as hex.

        The broker relays the frame to the lock and returns whatever the lock
        answered, so this carries *any* frame this integration builds, not only
        lock and unlock: a status query for the nonce, or a credential query for
        the host password, work the same way. That matters for accounts where
        `senddata` refuses everything with cod=930, because without it a command
        would be built from a stale nonce and the cloud's copy of the password,
        and the lock rejects that.

        Returns the ACK hex, or None if the publish failed, nothing answered in
        time, or the server reported a delivery error. A returned ACK is the
        lock's own reply and may still be a rejection — the caller parses it.
        """
        client = self._client
        if client is None or not self._connected:
            _LOGGER.debug(
                "Lockly MQTT: not connected, cannot exchange a frame for %s", device_id
            )
            return None

        request_id = str(uuid.uuid4())
        loop = self._hass.loop
        future: asyncio.Future = loop.create_future()
        self._pending[request_id] = future

        envelope = {
            "header": {
                "namespace": "com.lockly",
                "name": "lockCommandRequest",
                "requestId": request_id,
                "timestamp": int(time.time() * 1000),
            },
            "payload": {
                "deviceId": device_id,
                # "forward" is LockCommandRequestData.COMMAND_NAME: the server
                # forwards the frame to the lock rather than interpreting it.
                "commandName": "forward",
                "commandContent": base64.b64encode(bytes.fromhex(frame_hex)).decode(),
            },
        }
        try:
            info = await self._hass.async_add_executor_job(
                lambda: client.publish(
                    _PUBLISH_TOPIC, json.dumps(envelope, separators=(",", ":")), qos=1
                )
            )
            if getattr(info, "rc", 1) != 0:
                _LOGGER.warning(
                    "Lockly MQTT: publish failed locally for %s (rc=%s)",
                    device_id, getattr(info, "rc", "?"),
                )
                return None
            payload = await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "Lockly MQTT: no reply within %.0fs for %s", timeout, device_id
            )
            return None
        except Exception:  # noqa: BLE001 - an exchange failure must not break a command
            _LOGGER.exception("Lockly MQTT: exchange failed for %s", device_id)
            return None
        finally:
            self._pending.pop(request_id, None)

        # code 0 means the *server* delivered it. The lock's own verdict is
        # inside commandContent, so this is not success on its own — reporting
        # it as such once made a rejected command look like it had worked.
        code = payload.get("code")
        if code not in (0, "0", None):
            _LOGGER.warning(
                "Lockly MQTT: server rejected the command for %s — code=%s %s",
                device_id, code, payload.get("errorMessage"),
            )
            return None

        content = payload.get("commandContent")
        if not content:
            _LOGGER.warning(
                "Lockly MQTT: reply for %s carried no lock response", device_id
            )
            return None
        try:
            return base64.b64decode(content).hex().upper()
        except Exception:  # noqa: BLE001
            _LOGGER.warning(
                "Lockly MQTT: reply for %s was not decodable base64", device_id
            )
            return None

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
