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

# Values a deviceStateCallback carries for the states this reads. The word forms
# are what a Visage actually sends, captured on issues #5 and #10; the numeric
# ones are what the APK's own constants describe.
#
# `opened` was the expensive one. This set said `open`, so a door closing was
# recorded and a door opening was not — the sensor could go to closed and never
# back. It was reported as missed callbacks before anyone read the warning the
# unrecognised value was already logging.
_LOCKED_TRUE = frozenset({"1", "true", "locked"})
_LOCKED_FALSE = frozenset({"0", "false", "unlocked"})
_MAGNET_TRUE = frozenset({"1", "true", "open", "opened"})
_MAGNET_FALSE = frozenset({"0", "false", "close", "closed"})


def _as_bool(raw: object, true_set: frozenset, false_set: frozenset) -> bool | None:
    """Read one state value, or None when it is not a form we know."""
    value = str(raw).strip().lower()
    if value in true_set:
        return True
    if value in false_set:
        return False
    return None


def _as_percent(raw: object) -> int | None:
    """Read a battery percentage, or None when the value is not one.

    Anything outside 0-100 is refused rather than clamped. A lock reporting 255
    is saying something other than "full", and people set low-battery alerts off
    this number, so a wrong one is worse than none.
    """
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if 0 <= value <= 100 else None


# How much of a raw broker message the debug log keeps. This was 400, which cut
# every deviceStateCallback off mid-payload — the reporter on #2 sent a log to
# answer a question about the state keys and the state keys were the part that
# had been trimmed. A callback runs to roughly 600 characters and a command
# reply with its base64 frame to about 900, so 2000 keeps both whole with room
# to spare, and a message longer than that says how much it dropped rather than
# ending mid-word and looking like the message itself was malformed.
_LOG_PAYLOAD_LIMIT = 2000


def _mqtt_username(email: str, server_client_id: str | None = None) -> str:
    """The broker username, lowercased exactly as the app lowercases it.

    `Connection.createOptions` in the Lockly app does this and nothing else to
    the name it is given:

        String lowerCase = name.toLowerCase(Locale.ROOT);
        mqttConnectOptions.setUserName(lowerCase);

    Before 0.7.14 this integration sent the address exactly as typed into the
    config flow. It was a credible suspect for the rc=5 on #14 and was ruled
    out there — that reporter's address was already lowercase — but lowering
    it is still what the app does, so it stays.

    The prefix is the **Team ID**, not anything the server assigns.
    `MqttConnectionOption.getUserName()` builds `{prefix}_{email}` from
    `user_client_id_1208`, and in both decompiled apps the only thing that
    writes that key is a successful login, storing the value it was sent as
    `cloudId`. In LOCKLY 3.2.9 that is the login screen's "Team ID" box
    (`et_login_client_id`, re-sent on every launch by `SplashScreen`); in
    Lockly Home 1.4.8 it is empty for ordinary logins and set only by account
    migration. A regular account therefore has no prefix and connects as the
    bare address, which is what this integration does. Team (WorkSpace)
    accounts are not supported yet: they would need the Team ID sent at login
    and passed here. The app lowercases the whole composed string, so this
    does too.
    """
    name = f"{server_client_id}_{email}" if server_client_id else email
    return name.lower()


def _truncate(payload: bytes) -> str:
    """Decode a raw payload for the debug log, saying so if it is shortened."""
    text = payload.decode(errors="replace")
    if len(text) <= _LOG_PAYLOAD_LIMIT:
        return text
    return f"{text[:_LOG_PAYLOAD_LIMIT]}… [{len(text) - _LOG_PAYLOAD_LIMIT} more characters]"

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
        # Which entry of _brokers() the next connect uses. Advanced once, by a
        # refusal, so a second address gets one try before push is abandoned.
        self._broker_index = 0
        self._switching = False
        # requestId -> future awaiting that exchange's lockCommandResponse.
        self._pending: dict[str, asyncio.Future] = {}

    @property
    def connected(self) -> bool:
        """True once the broker has accepted the connection."""
        return self._connected

    def _brokers(self) -> list[tuple[str, int]]:
        """The broker addresses to try, in order.

        PgConfig's hardcoded address first: a network capture of the official
        app shows it connecting there, and on the account this was developed
        against the API-reported address refuses CONNECT with rc=5 where this
        one is accepted. That is one account's evidence, though, and the API
        hands out a different address to others — `mqtt-clb-…` is a real Lockly
        broker, seen in an official app's own traffic on #1. So the reported
        address is kept as a second candidate rather than discarded, because a
        refusal here costs the user all push and we only ever tried one host.

        Host and port travel together: a port from one broker's config means
        nothing against another's address.
        """
        candidates = [(_BROKER, _PORT)]
        api_host = getattr(self._coordinator, "mqtt_host", None)
        api_port = getattr(self._coordinator, "mqtt_port", None)
        if api_host and api_host != _BROKER:
            candidates.append((api_host, int(api_port or _PORT)))
        return candidates

    async def _switch_broker(self) -> None:
        """Restart the session against the next candidate address.

        `_switching` is already True — the connect handler raises it before
        stopping paho's loop, so the disconnection that teardown causes is not
        reported as a fault.
        """
        try:
            await self.async_stop()
            # The new address gets its own allowance; refusals from the one we
            # just left say nothing about this one.
            self._refusals = 0
            await self.async_start()
        finally:
            self._switching = False

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
                # A refusal on the first address is not proof the account has no
                # push — it may be the wrong broker for this account. If the API
                # named a different one, try that before writing push off.
                next_broker = self._broker_index + 1 < len(self._brokers())
                _LOGGER.warning(
                    "Lockly MQTT connection refused rc=%s%s — real-time push "
                    "disabled, polling continues",
                    rc,
                    " (not authorised; not retrying)"
                    if permanent and not next_broker
                    else "",
                )
                if (permanent or self._refusals >= _MAX_REFUSALS) and next_broker:
                    self._broker_index += 1
                    host, port = self._brokers()[self._broker_index]
                    _LOGGER.info(
                        "Lockly MQTT: trying %s:%s instead, the address "
                        "getHeartbeatTime reported for this account",
                        host, port,
                    )
                    # Set before stopping the loop, not inside the coroutine
                    # that runs later: loop_stop() trips on_disconnect, and
                    # without the flag already up that handler warns about a
                    # disconnection we caused on purpose — reporting one
                    # refusal twice.
                    self._switching = True
                    client.loop_stop()
                    self._hass.loop.call_soon_threadsafe(
                        self._hass.async_create_task, self._switch_broker()
                    )
                elif permanent or self._refusals >= _MAX_REFUSALS:
                    self._give_up()

        def on_disconnect(client, userdata, rc):
            self._connected = False
            if rc != 0 and not self._switching:
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
                    _truncate(msg.payload),
                )
                name = (data.get("header") or {}).get("name")
                if name == "deviceStateCallback":
                    self._hass.loop.call_soon_threadsafe(
                        self._hass.async_create_task,
                        self._process_device_state(data),
                    )
                elif name in ("lockCommandResponse", "deviceInfoResponse", "exception"):
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

            # The app's username is "{Team ID}_{email}" for a team account and
            # the bare email otherwise — see _mqtt_username. mqtt_client_id here
            # is getHeartbeatTime's value, which the app never uses for this; it
            # is always an echo of the id we sent and the coordinator discards
            # it, so in practice this is None and the username is the email.
            server_client_id = getattr(self._coordinator, "mqtt_client_id", None)
            username = _mqtt_username(email, server_client_id)
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
            # See _brokers() for why there is an order and what the second
            # entry is. _broker_index only moves when a connection is refused.
            candidates = self._brokers()
            host, port = candidates[min(self._broker_index, len(candidates) - 1)]
            if len(candidates) > 1:
                _LOGGER.debug(
                    "Lockly MQTT: %s of %s broker addresses — %s, with %s held "
                    "in reserve if this one refuses the connection",
                    self._broker_index + 1, len(candidates), host,
                    candidates[-1][0] if self._broker_index == 0 else candidates[0][0],
                )
            # The address is masked: this line is a routine paste into public
            # issues, and the diagnostic value is the client id and its
            # provenance, not who the account belongs to.
            log_username = _mqtt_username(mask_email(email), server_client_id)
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

    async def _exchange(
        self, header_name: str, payload: dict, device_id: str, timeout: float
    ) -> dict | None:
        """Publish one request and wait for the reply carrying our requestId.

        Shared by every request/response the broker serves. Returns the reply's
        payload, or None if the publish failed locally or nothing answered.
        """
        client = self._client
        if client is None or not self._connected:
            _LOGGER.debug(
                "Lockly MQTT: not connected, cannot send %s for %s",
                header_name, device_id,
            )
            return None

        request_id = str(uuid.uuid4())
        future: asyncio.Future = self._hass.loop.create_future()
        self._pending[request_id] = future
        envelope = {
            "header": {
                "namespace": "com.lockly",
                "name": header_name,
                "requestId": request_id,
                "timestamp": int(time.time() * 1000),
            },
            "payload": payload,
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
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            _LOGGER.warning(
                "Lockly MQTT: no reply within %.0fs for %s (%s)",
                timeout, device_id, header_name,
            )
            return None
        except Exception:  # noqa: BLE001 - a failure here must not break a command
            _LOGGER.exception("Lockly MQTT: exchange failed for %s", device_id)
            return None
        finally:
            self._pending.pop(request_id, None)

    async def async_device_info(
        self, device_id: str, timeout: float = _RESPONSE_TIMEOUT
    ) -> dict | None:
        """Ask the broker for a device's radio and firmware details.

        Returns the `deviceInfoResponse` payload:

            {"deviceId": ..., "bluetooth": {"address", "rssi",
             "rssiLastTimestamp", "currentTimestamp"},
             "wifi": {"address", "rssi", "ssid"},
             "version": {"firemwareVersion"}}

        `bluetooth.rssi` is the hub-to-lock signal, which is the only way to
        measure why a particular lock keeps timing out rather than infer it from
        where the hub is sitting. The app treats a reading whose
        `rssiLastTimestamp` is more than 15 seconds behind `currentTimestamp` as
        expired, so freshness has to be checked rather than assumed.
        """
        payload = await self._exchange(
            "deviceInfoRequest", {"deviceId": device_id}, device_id, timeout
        )
        if payload is None:
            return None
        code = payload.get("code")
        if code not in (0, "0", None):
            _LOGGER.warning(
                "Lockly MQTT: device info refused for %s — code=%s %s",
                device_id, code, payload.get("errorMessage") or payload.get("message"),
            )
            return None
        return payload

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

        payload = await self._exchange(
            "lockCommandRequest",
            {
                "deviceId": device_id,
                # "forward" is LockCommandRequestData.COMMAND_NAME: the server
                # forwards the frame to the lock rather than interpreting it.
                "commandName": "forward",
                "commandContent": base64.b64encode(bytes.fromhex(frame_hex)).decode(),
            },
            device_id,
            timeout,
        )
        if payload is None:
            return None

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
        # The item list arrives under "payload", the same as every other message
        # this client handles. It was read from the root here for a long time,
        # from an APK reading no capture ever confirmed, so every callback the
        # broker sent was dropped — which is why external changes looked
        # impossible to receive. Captured from a Visage on issue #5. The root
        # form is still accepted: it costs one lookup and may be what other
        # firmware sends.
        payload = data.get("payload") or {}
        items = payload.get("items") or data.get("items") or []
        for item in items:
            device_id = (item.get("deviceId") or "").lower()
            raw_states = item.get("states") or []
            states = {s["statusKey"]: s["statusValue"] for s in raw_states if "statusKey" in s}
            _LOGGER.debug("DEVICE_STATE lock=%s states=%s", device_id, states)

            if not self._coordinator.data or device_id not in self._coordinator.data:
                _LOGGER.debug("DEVICE_STATE: unknown lock %s — ignoring", device_id)
                continue

            update: dict = {}
            for key, raw in states.items():
                name = key.lower()
                if name in ("lock", "locked_status"):
                    value = _as_bool(raw, _LOCKED_TRUE, _LOCKED_FALSE)
                    field = "is_locked"
                elif name == "magnet":
                    value = _as_bool(raw, _MAGNET_TRUE, _MAGNET_FALSE)
                    field = "door_sensor_open"
                elif name == "battery":
                    value = _as_percent(raw)
                    field = "battery_percent"
                else:
                    continue
                if value is None:
                    # Say so rather than picking one. A wrong answer about a
                    # lock or a door is worse than admitting the value is not
                    # recognised, and this is how the next unseen form of it
                    # gets reported instead of silently becoming False.
                    _LOGGER.warning(
                        "Lockly MQTT: %s sent %s=%r, which is not a value this "
                        "understands — state left unchanged. Please report it",
                        device_id, key, raw,
                    )
                    continue
                update[field] = value

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
