"""Lockly MQTT manager — real-time lock state via Lockly Paho broker."""
from __future__ import annotations

import json
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
_TOPIC = "server"

# Give up after this many non-permanent refusals rather than reconnecting forever.
_MAX_REFUSALS = 3

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

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                self._connected = True
                # Logged at info: without it there is no way to tell a working
                # push connection from one that silently never connected.
                _LOGGER.info("Lockly MQTT connected, subscribing to %r", _TOPIC)
                client.subscribe(_TOPIC, qos=0)
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
            if any(int(c) == 0x80 for c in codes):
                _LOGGER.warning(
                    "Lockly MQTT: broker REFUSED the subscription to %r "
                    "(SUBACK 0x80) — connected, but no push messages will "
                    "arrive; state falls back to polling",
                    _TOPIC,
                )
                # Holding the session open achieves nothing once the only topic
                # we want has been refused, so drop it rather than keeping a
                # pointless connection alive.
                self._give_up()
            else:
                _LOGGER.info(
                    "Lockly MQTT subscribed to %r at qos=%s", _TOPIC, codes
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
