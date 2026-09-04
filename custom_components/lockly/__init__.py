"""Lockly smart lock Home Assistant integration."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import aiohttp
import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    api_cached_status,
    api_get_devices,
    api_get_heartbeat,
    api_get_lock_history,
    api_add_guest,
    api_delete_guest,
    api_list_guests,
    api_lock,
    api_login,
    api_query_lock_status,
    api_query_lock_log,
    api_query_lock_log_paged,
    api_query_passwords,
    build_lock_cmd,
    build_unlock_cmd,
    api_unlock,
    describe_open_type,
    host_password_from,
)
from .capabilities import LockCapabilities, resolve_capabilities
from .mqtt import LocklyMQTTManager
from .const import (
    CONF_EMAIL,
    CONF_PASSWORD,
    DOMAIN,
    HISTORY_INITIAL_DELAY_SECONDS,
    HISTORY_INTERVAL_SECONDS,
    HISTORY_LOOKBACK_DAYS,
    LIVE_INIT_MAX_ATTEMPTS,
    LIVE_INIT_REARM_SECONDS,
    SCAN_INTERVAL_SECONDS,
    SERVICE_ADD_GUEST,
    SERVICE_DELETE_GUEST,
    SERVICE_LIST_GUESTS,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["binary_sensor", "lock", "sensor"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    coordinator = LocklyCoordinator(hass, entry)

    try:
        await coordinator.async_config_entry_first_refresh()
    except ConfigEntryAuthFailed:
        raise
    except Exception as exc:
        raise ConfigEntryNotReady from exc

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    coordinator.async_start_history_polling()
    coordinator._mqtt_manager = LocklyMQTTManager(hass, coordinator)
    await coordinator._mqtt_manager.async_start()
    _register_services(hass, coordinator)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        coordinator: LocklyCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_shutdown()
        # The services are domain-wide, so only tear them down with the last
        # entry — otherwise unloading one account removes them for the others.
        if not hass.data[DOMAIN]:
            for svc in (SERVICE_LIST_GUESTS, SERVICE_ADD_GUEST, SERVICE_DELETE_GUEST):
                hass.services.async_remove(DOMAIN, svc)
            hass.data.pop(DOMAIN, None)
    return unloaded


class LocklyCoordinator(DataUpdateCoordinator):
    """Polls all Lockly locks and maintains session state."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        self.config_entry = entry
        self.email: str = entry.data[CONF_EMAIL]
        self.password: str = entry.data[CONF_PASSWORD]
        self.jwt: str | None = None
        self.des3_key: bytes | None = None
        self.locks: list[dict] = []
        self._session: aiohttp.ClientSession | None = None
        # True until we confirm cached-status is unsupported for this hub.
        self._cache_supported: bool = True
        # Lock ID -> live-status attempts so far.  Present means still trying;
        # removed means either seeded successfully or given up on.
        self._live_init_attempts: dict[str, int] = {}
        # Lock ID -> loop time at which a given-up lock may be probed again.
        self._live_init_retry_at: dict[str, float] = {}
        # Access log polling state.
        self._history_cursors: dict[str, int] = {}  # lock_id -> LAST_EVENT_SYNC_TIME ms
        self._history_cancel: list = []
        # Per-lock frame capabilities, learned from the lock type each lock
        # reports in its status ACK.  Until then the app's own fallback applies.
        self._capabilities: dict[str, LockCapabilities] = {}
        # Last nonce each lock returned; replayed in the next command it receives.
        self._nonces: dict[str, str] = {}
        # Host password read from each lock, which is authoritative over the
        # cloud's "hc" copy.  None means "queried and the lock had no slot 0".
        self._host_passwords: dict[str, str | None] = {}
        # Locks whose cloud access log is barren and whose cursor never moves;
        # these are read from the lock itself instead.
        self._cloud_history_exhausted: set[str] = set()
        # Record ids already surfaced from a lock's own log, so re-reading it
        # does not re-fire events for activity we have already reported.
        self._seen_log_ids: dict[str, set] = {}
        # Locks whose bulk log read has failed; these use the paged query only.
        self._prefer_paged_log: set[str] = set()
        # Locks whose access log has been read this session.  Reading it wakes
        # the lock, so it is done once and then only on request.
        self._lock_log_read: set[str] = set()
        # Locks observed reporting a CLOSED door circuit, which only a fitted
        # sensor can produce.  Used to gate the door sensor entity.
        self._door_sensor_proven: set[str] = set()
        # MQTT push configuration from getHeartbeatTime.  The broker authorises
        # subscriptions by client identity, and client_id is the only one the
        # API exposes; None means we never got it and fall back to defaults.
        self.mqtt_client_id: str | None = None
        self.mqtt_host: str | None = None
        self.mqtt_port: int | None = None

    async def _ensure_session(self) -> None:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()

    async def _authenticate(self) -> None:
        await self._ensure_session()
        self.jwt = await api_login(self._session, self.email, self.password)
        if not self.jwt:
            raise ConfigEntryAuthFailed("Lockly login failed — check email/password")
        self.locks, self.des3_key = await api_get_devices(self._session, self.jwt, self.email)
        if not self.locks:
            raise UpdateFailed("Lockly: no locks found after login")
        # The broker authorises subscriptions by client identity, so fetch the
        # push config before (re)connecting.  Uses the config entry id as a
        # stable per-install device id, standing in for the app's own.
        heartbeat = await api_get_heartbeat(
            self._session, self.jwt, self.des3_key, self.config_entry.entry_id
        )
        if heartbeat:
            client_id = heartbeat.get("client_id")
            # The endpoint echoes back the device id it was given rather than
            # assigning one, so an equal value carries no information.  Treating
            # it as real builds the broker username "{our own id}_{email}", and
            # the broker rejects that outright where the bare email is at least
            # accepted.  A fabricated identity is worse than none.
            echoed = bool(client_id) and client_id == self.config_entry.entry_id
            self.mqtt_client_id = None if echoed else client_id
            self.mqtt_host = heartbeat.get("host")
            self.mqtt_port = heartbeat.get("port")
            _LOGGER.info(
                "Lockly: MQTT config from getHeartbeatTime — client_id=%s host=%s port=%s",
                "echoed back (ignored)" if echoed
                else ("present" if self.mqtt_client_id else "absent"),
                self.mqtt_host or "(default)",
                self.mqtt_port or "(default)",
            )

        # The MQTT broker authenticates with the JWT, so a rotated token needs a
        # fresh session or push stops silently.
        mqtt = getattr(self, "_mqtt_manager", None)
        if mqtt is not None:
            await mqtt.async_reconnect()
        self._cache_supported = True
        self._live_init_attempts = {lock["ID"]: 0 for lock in self.locks}
        self._live_init_retry_at.clear()
        _LOGGER.info("Lockly: authenticated, found %d lock(s)", len(self.locks))
        for lock in self.locks:
            name = lock.get("na") or lock.get("blename") or lock["ID"]
            missing = [f for f in ("mc", "hc", "hubid") if not lock.get(f)]
            if missing:
                _LOGGER.warning(
                    "Lockly: lock %s is missing %s — commands will fail without it",
                    name, ", ".join(missing),
                )
            # Model/firmware/topology only; mc, hc, iotsecret and iotprodkey are
            # credentials and must never reach the log.  clientId and iotdm are
            # reported as present/absent rather than by value: whether they are
            # populated is the diagnostic, and the values are device identities.
            _LOGGER.debug(
                "Lockly lock %s: model=%s fw=%s hub=%s hubver=%s gw=%s/%s "
                "dutype=%s ekey=%s otlk=%s subadm=%s/%s iotdm=%s clientId=%s caps=%s",
                name, lock.get("mod"), lock.get("fwv"),
                lock.get("hubid") or "(none)", lock.get("hubver"),
                lock.get("gwModel"), lock.get("gwver"),
                lock.get("dutype"), lock.get("ekeyType") or "(empty)",
                lock.get("otlkmod"), lock.get("subadm"), lock.get("secondAdm"),
                "set" if lock.get("iotdm") else "empty",
                "set" if lock.get("clientId") else "empty",
                self._caps_for(lock),
            )

    def _caps_for(self, lock: dict) -> LockCapabilities:
        """Capabilities for a lock, using its reported lock type when known."""
        lock_id = lock["ID"]
        if lock_id not in self._capabilities:
            self._capabilities[lock_id] = resolve_capabilities(lock)
        return self._capabilities[lock_id]

    def _learn_from_status(self, lock: dict, status: dict) -> None:
        """Record the lock type and nonce a status response revealed."""
        lock_id = lock["ID"]
        lock_type = status.get("lock_type")
        if lock_type is not None:
            known = self._capabilities.get(lock_id)
            if known is None or known.lock_type != lock_type:
                caps = resolve_capabilities(lock, lock_type=lock_type)
                self._capabilities[lock_id] = caps
                _LOGGER.debug(
                    "Lockly: lock %s reports %s",
                    lock.get("na") or lock.get("blename") or lock_id, caps,
                )
                if caps.needs_firmware_check:
                    _LOGGER.warning(
                        "Lockly: lock %s (type %d) selects its command format by "
                        "firmware version, which is not implemented — falling back "
                        "to the 0x22 frame. Please report this on GitHub.",
                        lock.get("blename") or lock_id, caps.lock_type,
                    )
        # A door-circuit reading of "closed" can only come from a fitted sensor —
        # an unfitted one is an open circuit and always reads open.  So observing
        # closed once proves a sensor exists, and from then on an "open" reading
        # for that lock means the door, not a missing sensor.  Locks that never
        # read closed are left unproven, which is the honest answer: their
        # constant "open" is indistinguishable from having no sensor at all.
        if status.get("door_sensor_open") is False and lock_id not in self._door_sensor_proven:
            self._door_sensor_proven.add(lock_id)
            _LOGGER.info(
                "Lockly: %s has a working door sensor (reported a closed door)",
                lock.get("na") or lock.get("blename") or lock_id,
            )

        nonce = status.get("ble_nonce")
        if nonce:
            self._nonces[lock_id] = nonce

    async def _async_update_data(self) -> dict:
        await self._ensure_session()

        if not self.jwt or self.des3_key is None or not self.locks:
            await self._authenticate()

        result: dict = {}
        any_ok = False
        cache_failed_count = 0

        for lock in self.locks:
            lock_id = lock["ID"]
            status = None

            if self._cache_supported:
                status = await api_cached_status(
                    self._session, self.jwt, self.des3_key, self.email, lock
                )
                if status is None:
                    cache_failed_count += 1

            # Live query to seed initial state when the cache is unavailable.
            # Bounded retries, one per poll cycle: discarding after a single
            # attempt meant a transient NACK or hub relay timeout cost the lock
            # its state — and its door sensor entity — until HA restarted. The
            # cap is what stops this being a poll loop, because every attempt
            # wakes the lock and some models beep when woken.
            attempts = self._live_init_attempts.get(lock_id)
            if status is None and attempts is not None:
                attempts += 1
                self._live_init_attempts[lock_id] = attempts
                status = await api_query_lock_status(
                    self._session, self.jwt, self.email, self.des3_key, lock
                )
                if status:
                    del self._live_init_attempts[lock_id]
                elif attempts >= LIVE_INIT_MAX_ATTEMPTS:
                    del self._live_init_attempts[lock_id]
                    self._live_init_retry_at[lock_id] = (
                        self.hass.loop.time() + LIVE_INIT_REARM_SECONDS
                    )
                    _LOGGER.warning(
                        "Lockly: %s returned no status in %d attempts — its "
                        "state and door sensor stay unavailable for now; "
                        "retrying quietly every %d minutes",
                        lock.get("na") or lock.get("blename") or lock_id,
                        LIVE_INIT_MAX_ATTEMPTS,
                        LIVE_INIT_REARM_SECONDS // 60,
                    )
            elif status is None and lock_id in self._live_init_retry_at:
                # A lock we gave up on. One probe per interval, so a hub that
                # comes back is picked up on its own — previously the only
                # recovery was restarting HA, which meant a lock could sit
                # stateless indefinitely after a transient hub failure. Silent
                # on failure: the warning above was already logged once, and
                # repeating it every interval would just be noise.
                if self.hass.loop.time() >= self._live_init_retry_at[lock_id]:
                    self._live_init_retry_at[lock_id] = (
                        self.hass.loop.time() + LIVE_INIT_REARM_SECONDS
                    )
                    status = await api_query_lock_status(
                        self._session, self.jwt, self.email, self.des3_key, lock
                    )
                    if status:
                        del self._live_init_retry_at[lock_id]
                        _LOGGER.info(
                            "Lockly: %s is responding again",
                            lock.get("na") or lock.get("blename") or lock_id,
                        )

            if status:
                self._learn_from_status(lock, status)
                result[lock_id] = {
                    **lock,
                    **status,
                    # Only meaningful once a closed reading has proven a sensor
                    # exists; before that an "open" circuit is indistinguishable
                    # from no sensor being fitted.
                    "wired_door_sensor_connected": lock_id in self._door_sensor_proven,
                }
                any_ok = True
            elif self.data and lock_id in self.data:
                result[lock_id] = self.data[lock_id]
                any_ok = True  # kept from previous good state
            else:
                result[lock_id] = dict(lock)

        if self._cache_supported and cache_failed_count == len(self.locks) and self.locks:
            _LOGGER.info(
                "Lockly: cachedstatus unsupported for this hub (hub firmware too old) — "
                "state will only update after HA commands"
            )
            self._cache_supported = False

        if not any_ok and self.locks:
            _LOGGER.warning("All lock queries failed — forcing re-login next cycle")
            self.jwt = None

        return result

    async def _refresh_nonce(self, lock: dict) -> str | None:
        """Live status query immediately before a command, to sync the nonce.

        The lock replays the nonce from its own last status response, and that
        value changes as the lock is used (physical entry, BLE reconnect).  A
        stale nonce gets the command NACKed, so we refresh it rather than
        trusting whatever we last saw — which may be from hours ago.
        """
        lock_id = lock["ID"]
        status = await api_query_lock_status(
            self._session, self.jwt, self.email, self.des3_key, lock
        )
        if status:
            self._learn_from_status(lock, status)
            if self.data and lock_id in self.data:
                self.async_set_updated_data(
                    {**self.data, lock_id: {**self.data[lock_id], **status}}
                )
        else:
            _LOGGER.debug(
                "Lockly: pre-command status query failed for %s — reusing last "
                "known nonce, which the lock may reject",
                lock.get("blename") or lock_id,
            )
        return self._nonces.get(lock_id)

    async def _resolve_host_password(self, lock: dict, nonce: str | None) -> str | None:
        """Read the host password from the lock, caching it for the session.

        The cloud's ``hc`` is a copy that the app updates locally whenever the
        host code changes on the lock, so it can be stale — and a stale password
        is rejected with BLE error FF ("wrong password").  Asking the lock is
        what the app itself does; ``hc`` stays as the fallback.
        """
        lock_id = lock["ID"]
        if lock_id in self._host_passwords:
            return self._host_passwords[lock_id]

        entries = await api_query_passwords(
            self._session, self.jwt, self.email, self.des3_key, lock,
            nonce=nonce, caps=self._caps_for(lock),
        )
        if entries is None:
            # Do not cache a failure — a transient hub timeout should be retried.
            return None

        host_pwd = host_password_from(entries)
        self._host_passwords[lock_id] = host_pwd
        cloud_hc = str(lock.get("hc") or "")
        # Per-entry shape, so a misaligned walk is visible rather than inferred:
        # a wrong step yields implausible user_type or length values.  Lengths
        # only — never the passwords themselves.
        _LOGGER.debug(
            "Lockly: lock %s credential entries (type/slot/len): %s",
            lock.get("blename") or lock_id,
            [
                (e.get("user_type"), e.get("pwd_id"), len(e.get("password") or ""))
                for e in entries
            ],
        )
        _LOGGER.warning(
            "Lockly: lock %s reports %d credential(s), slots %s; host slot 0 "
            "present=%s, matches cloud hc=%s",
            lock.get("blename") or lock_id,
            len(entries),
            sorted({e.get("pwd_id") for e in entries}),
            host_pwd is not None,
            (host_pwd == cloud_hc) if host_pwd is not None else "n/a",
        )
        return host_pwd

    async def _send_command(self, lock_id: str, *, unlock: bool) -> bool:
        lock = self._get_lock(lock_id)
        if lock is None:
            _LOGGER.warning("Lockly: lock_id %s is not in the discovered lock list", lock_id)
            return False
        nonce = await self._refresh_nonce(lock)
        host_pwd = await self._resolve_host_password(lock, nonce)
        action = api_unlock if unlock else api_lock
        ok = await action(
            self._session, self.jwt, self.email, self.des3_key, lock,
            nonce=nonce, caps=self._caps_for(lock),
            lock_pwd_override=host_pwd,
        )
        if ok:
            self._set_optimistic_lock_state(lock_id, is_locked=not unlock)
            return True

        _LOGGER.warning(
            "Lockly: %s failed for %s — see the senddata warning above",
            "unlock" if unlock else "lock",
            lock.get("na") or lock.get("blename") or lock_id,
        )
        # Second transport. The app reaches some locks over the MQTT broker
        # rather than senddata, which is why a few accounts get cod=930 from
        # senddata while their app works fine. No optimistic state update here:
        # a queued publish is not an acted-on command, and the server replies
        # asynchronously on the client topic.
        return await self._try_mqtt_command(lock, nonce, host_pwd, unlock=unlock)

    async def _try_mqtt_command(
        self, lock: dict, nonce: str | None, host_pwd: str | None, *, unlock: bool
    ) -> bool:
        """Publish a command over MQTT after senddata refused it.

        Implemented but not verified end to end: on the only hardware available
        to test, the broker accepts the publish and answers `3005 device is
        offline`, meaning that hub is not connected to this channel. The frame
        is the same one senddata carries, so nothing new is being guessed at.
        """
        mqtt = getattr(self, "_mqtt_manager", None)
        if mqtt is None or not mqtt.connected:
            return False
        builder = build_unlock_cmd if unlock else build_lock_cmd
        frame = builder(
            str(lock["mc"]), lock["ID"], host_pwd or "", nonce,
            caps=self._caps_for(lock),
        )
        _LOGGER.info(
            "Lockly: retrying %s for %s over MQTT",
            "unlock" if unlock else "lock",
            lock.get("na") or lock.get("blename") or lock["ID"],
        )
        return await mqtt.async_send_lock_command(lock["ID"], frame)

    async def async_unlock_lock(self, lock_id: str) -> bool:
        return await self._send_command(lock_id, unlock=True)

    async def async_lock_lock(self, lock_id: str) -> bool:
        return await self._send_command(lock_id, unlock=False)

    def _set_optimistic_lock_state(self, lock_id: str, is_locked: bool) -> None:
        if self.data and lock_id in self.data:
            updated = {**self.data, lock_id: {**self.data[lock_id], "is_locked": is_locked}}
            self.async_set_updated_data(updated)

    def _get_lock(self, lock_id: str) -> dict | None:
        return next((l for l in self.locks if l["ID"] == lock_id), None)

    def async_start_history_polling(self) -> None:
        """Register the access log poll timer and do one fetch shortly after setup.

        ``async_track_time_interval`` only fires after a full interval, and HA
        can take minutes to reach this integration, so waiting for the first
        tick leaves Last Access blank for roughly ten minutes after a restart —
        and any restart inside that window resets the clock without a single
        fetch ever happening.  A short initial delay avoids that while still
        staying clear of the startup burst.
        """
        cancel = async_track_time_interval(
            self.hass,
            self._async_poll_history,
            timedelta(seconds=HISTORY_INTERVAL_SECONDS),
        )
        self._history_cancel.append(cancel)
        self._history_cancel.append(
            async_call_later(
                self.hass, HISTORY_INITIAL_DELAY_SECONDS, self._async_poll_history
            )
        )

    @staticmethod
    def _resolve_operator(lock: dict, event: dict) -> tuple[str | None, list[str]]:
        """Best-effort name for whoever triggered an access event.

        ``na`` is only filled in for app-initiated actions.  A keypad or
        fingerprint entry is anonymous there, and the only identifying field is
        ``pid``, the credential slot.  The lock's ``usrarr`` maps slots to names,
        but slot numbers are namespaced per credential type — a fingerprint and a
        passcode can both be pid 1 — and the event does not record which type it
        was.  So resolve only when exactly one user matches, and report the
        candidates rather than picking one arbitrarily.

        Returns (name, ambiguous_candidates).
        """
        stated = str(event.get("na") or "").strip()
        if stated:
            return stated, []
        pid = event.get("pid")
        if pid is None:
            return None, []
        names = set()
        for user in lock.get("usrarr") or []:
            if user.get("pid") != pid:
                continue
            name = f"{user.get('fn') or ''} {user.get('ln') or ''}".strip()
            if name:
                names.add(name)
        candidates = sorted(names)
        if len(candidates) == 1:
            return candidates[0], []
        return None, candidates

    def _history_start_cursor(self) -> int:
        """Where to begin reading the access log on first sync.

        Deliberately 0.  Seeding this to a recent timestamp seemed reasonable —
        it avoids replaying old records — but in practice it returns nothing at
        all for every lock, so ``time`` is not the "events after this" filter it
        looks like.  Passing 0 does return events, so that is what we do, and
        stale records are filtered on the way out instead (see
        ``_is_recent_event``).
        """
        return 0

    async def _maybe_read_lock_log(self, lock: dict, force: bool = False) -> None:
        """Read the lock's access log at most once per session, unless forced.

        Reading it goes over senddata, which wakes the lock — and a woken lock
        beeps if its BLE sound is enabled, as well as costing battery.  Doing
        that on the recurring poll made locks beep every few minutes, which is
        exactly the trap AGENTS.md warns about: never call senddata from a poll
        loop.

        So the log is read once shortly after setup, and thereafter only when
        asked for via lockly.read_access_log.  The cost of that is a Last Access
        value that does not refresh on its own; the alternative is a lock that
        beeps at the household every five minutes.
        """
        lock_id = lock["ID"]
        if not force and lock_id in self._lock_log_read:
            return
        self._lock_log_read.add(lock_id)
        await self._poll_lock_log(lock)

    async def _poll_lock_log(self, lock: dict) -> None:
        """Read the access log from the lock itself and surface recent records.

        Used where the cloud log is barren.  This wakes the lock, so it is only
        reached once the cloud path has been shown to be useless for that lock.
        """
        lock_id = lock["ID"]
        nonce = self._nonces.get(lock_id)
        caps = self._caps_for(lock)
        cutoff = self._history_cutoff_ms()

        if lock_id in self._prefer_paged_log:
            records = None
        else:
            records = await api_query_lock_log(
                self._session, self.jwt, self.email, self.des3_key, lock,
                nonce=nonce, caps=caps,
            )

        if records is None:
            # The bulk read returns the whole log in one response, which some
            # locks' BLE links cannot carry — it comes back as a hub timeout or
            # a Bluetooth error.  The paged form asks for a bounded window
            # instead, so the response is small enough to get through.
            _LOGGER.debug(
                "Lockly lock log: %s bulk read unavailable, trying the paged query",
                lock.get("blename") or lock_id,
            )
            records = await api_query_lock_log_paged(
                self._session, self.jwt, self.email, self.des3_key, lock,
                start_ms=cutoff, end_ms=None, nonce=nonce, caps=caps,
            )
            if records:
                # Stop paying for a bulk attempt that has already been shown to
                # fail on this lock.
                self._prefer_paged_log.add(lock_id)

        if not records:
            _LOGGER.debug(
                "Lockly lock log: %s read failed (bulk and paged)",
                lock.get("blename") or lock_id,
            )
            return

        cutoff = self._history_cutoff_ms()
        recent = [r for r in records if self._is_recent_event(r, cutoff)]
        _LOGGER.debug(
            "Lockly lock log: %s returned %d record(s), %d recent",
            lock.get("blename") or lock_id, len(records), len(recent),
        )
        if not recent:
            return

        seen = self._seen_log_ids.setdefault(lock_id, set())
        for record in sorted(recent, key=lambda r: r.get("tm") or 0):
            if record.get("id") in seen:
                continue
            seen.add(record.get("id"))
            operator, candidates = self._resolve_operator(lock, record)
            record["operator"] = operator
            record["operator_candidates"] = candidates
            self.hass.bus.async_fire(
                "lockly_lock_event",
                {
                    "lock_id": lock_id,
                    "lock_name": lock.get("na") or lock.get("blename") or lock_id,
                    "event_type": describe_open_type(record.get("co")),
                    "event_code": record.get("co"),
                    "user_id": str(record.get("pid") if record.get("pid") is not None else ""),
                    "user_name": operator or "",
                    "operator_candidates": candidates,
                    "timestamp": record.get("tm") or 0,
                    "event_id": record.get("id") or 0,
                    "source": "lock",
                },
            )

        if self.data and lock_id in self.data:
            # Prefer the most recent record that identifies somebody.  Many
            # records carry the "no credential" sentinel — auto-lock and door
            # events — and reporting one of those as the last access answers a
            # different question than the sensor is asking.
            attributable = [r for r in recent if r.get("pid") is not None]
            latest = max(attributable or recent, key=lambda r: r.get("tm") or 0)
            self.async_set_updated_data(
                {**self.data, lock_id: {**self.data[lock_id], "last_access_event": latest}}
            )

    def _history_cutoff_ms(self) -> int:
        """Timestamp below which an access-log record is not worth surfacing."""
        lookback = timedelta(days=HISTORY_LOOKBACK_DAYS)
        return int((datetime.now(timezone.utc) - lookback).timestamp() * 1000)

    @staticmethod
    def _is_recent_event(event: dict, cutoff_ms: int) -> bool:
        """Whether an event is recent enough to surface.

        Filtering happens here rather than via the request cursor because the
        cursor does not filter reliably, and because some locks report events
        with implausible timestamps — high event ids carrying dates years in the
        past, which looks like a lock whose clock was never set. Those must not
        be presented as the most recent access.
        """
        tm = event.get("tm") or 0
        return tm >= cutoff_ms

    async def _async_poll_history(self, _now=None) -> None:
        if not self.jwt or self.des3_key is None or not self.locks:
            return
        await self._ensure_session()
        for lock in self.locks:
            lock_id = lock["ID"]
            since_ms = self._history_cursors.get(lock_id)
            if since_ms is None:
                since_ms = self._history_start_cursor()
                self._history_cursors[lock_id] = since_ms
            if lock_id in self._cloud_history_exhausted:
                # getlkhist has already proven barren for this lock; re-asking
                # returns the same dead page forever.  Reading the log from the
                # lock is NOT done here: it goes over senddata, which wakes the
                # lock and makes it beep, and this runs every few minutes.  It
                # happens once at startup and on demand instead — see
                # _maybe_read_lock_log.
                await self._maybe_read_lock_log(lock)
                continue

            result = await api_get_lock_history(
                self._session, self.jwt, self.des3_key, self.email, lock_id, since_ms
            )
            if result is None:
                _LOGGER.debug(
                    "Lockly history: %s request FAILED (cursor was %s)",
                    lock.get("blename") or lock_id, since_ms,
                )
                continue
            events, new_cursor = result
            # Logged even when empty: otherwise a lock that never returns events
            # is indistinguishable from one that was never polled.
            _LOGGER.debug(
                "Lockly history: %s returned %d event(s), cursor %s -> %s",
                lock.get("blename") or lock_id, len(events), since_ms, new_cursor,
            )
            if new_cursor > since_ms:
                self._history_cursors[lock_id] = new_cursor

            # Advance the cursor through everything, but only surface recent
            # records.  Old ones still move the sync point forward; firing them
            # would flood the bus and would make "last access" report a date
            # from years ago.
            cutoff = self._history_cutoff_ms()
            recent = [e for e in events if self._is_recent_event(e, cutoff)]
            if events and not recent:
                oldest = min(e.get("tm") or 0 for e in events)
                newest = max(e.get("tm") or 0 for e in events)
                _LOGGER.debug(
                    "Lockly history: %s — all %d event(s) older than the cutoff "
                    "(tm range %s..%s, cutoff %s); advancing the cursor",
                    lock.get("blename") or lock_id, len(events), oldest, newest, cutoff,
                )

            for event in recent:
                _LOGGER.debug("lockly history event raw: %s", event)
                operator, candidates = self._resolve_operator(lock, event)
                # Resolution is attached to the event so the sensor and the bus
                # event agree, and so it is computed once per event.
                event["operator"] = operator
                event["operator_candidates"] = candidates
                self.hass.bus.async_fire(
                    "lockly_lock_event",
                    {
                        "lock_id": lock_id,
                        "lock_name": lock.get("na") or lock.get("blename") or lock_id,
                        "event_type": describe_open_type(event.get("co")),
                    "event_code": event.get("co"),
                        "user_id": str(event.get("pid") if event.get("pid") is not None else ""),
                        "user_name": operator or "",
                        "operator_candidates": candidates,
                        "timestamp": event.get("tm") or 0,
                        "event_id": event.get("id") or 0,
                    },
                )
            # Update last_access_event on coordinator data so the sensor reflects it.
            # Use the event with the largest tm value (getlkhist returns oldest-first).
            # Decide whether the cloud log is worth asking again.  A cursor that
            # does not advance means we will be handed the same page forever, so
            # once that page has nothing recent in it there is nothing to gain.
            if new_cursor <= since_ms and not recent:
                self._cloud_history_exhausted.add(lock_id)
                _LOGGER.info(
                    "Lockly: %s — the cloud access log has no recent records and "
                    "its cursor does not advance; reading the log from the lock "
                    "instead",
                    lock.get("blename") or lock_id,
                )
                await self._maybe_read_lock_log(lock)

            if recent and self.data and lock_id in self.data:
                latest = max(recent, key=lambda e: e.get("tm", 0))
                updated = {
                    **self.data,
                    lock_id: {**self.data[lock_id], "last_access_event": latest},
                }
                self.async_set_updated_data(updated)

    async def async_shutdown(self) -> None:
        if hasattr(self, "_mqtt_manager"):
            await self._mqtt_manager.async_stop()
        for cancel in self._history_cancel:
            cancel()
        self._history_cancel.clear()
        if self._session and not self._session.closed:
            await self._session.close()


# ── Service schemas ───────────────────────────────────────────────────────────

_LIST_GUESTS_SCHEMA = vol.Schema({
    vol.Required("lock_id"): cv.string,
})

_ADD_GUEST_SCHEMA = vol.Schema({
    vol.Required("lock_id"): cv.string,
    vol.Required("name"): cv.string,
    vol.Required("passcode"): vol.All(cv.string, vol.Match(r"^\d{4,8}$")),
    vol.Optional("duration_hours", default=24): vol.All(vol.Coerce(int), vol.Range(min=1, max=8760)),
    vol.Optional("start_time"): cv.datetime,
    vol.Optional("end_time"): cv.datetime,
})

_DELETE_GUEST_SCHEMA = vol.Schema({
    vol.Required("lock_id"): cv.string,
    vol.Required("user_acu_id"): vol.Coerce(int),
})


def _register_services(hass: HomeAssistant, coordinator: LocklyCoordinator) -> None:
    """Register lockly.list_guests, lockly.add_guest, lockly.delete_guest services."""

    async def handle_list_guests(call) -> None:
        lock_id = call.data["lock_id"]
        lock = coordinator._get_lock(lock_id)
        if lock is None:
            _LOGGER.error("list_guests: lock_id %s not found", lock_id)
            return
        admin_acu_id = int(lock.get("adminAcuId") or 0)
        guests = await api_list_guests(
            coordinator._session, coordinator.jwt, coordinator.des3_key,
            lock_id, admin_acu_id,
        )
        hass.bus.async_fire("lockly_guest_list", {
            "lock_id": lock_id,
            "guests": guests or [],
        })

    async def handle_add_guest(call) -> None:
        lock_id = call.data["lock_id"]
        lock = coordinator._get_lock(lock_id)
        if lock is None:
            _LOGGER.error("add_guest: lock_id %s not found", lock_id)
            return
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        if "start_time" in call.data and "end_time" in call.data:
            start_ms = int(call.data["start_time"].timestamp() * 1000)
            end_ms = int(call.data["end_time"].timestamp() * 1000)
        else:
            hours = call.data.get("duration_hours", 24)
            start_ms = now_ms
            end_ms = now_ms + hours * 3_600_000
        result = await api_add_guest(
            coordinator._session, coordinator.jwt, coordinator.des3_key,
            lock_id, call.data["name"], call.data["passcode"],
            start_ms, end_ms,
        )
        hass.bus.async_fire("lockly_guest_added", {
            "lock_id": lock_id,
            "success": result is not None,
            "user_acu_id": (result or {}).get("userAcuId"),
        })

    async def handle_delete_guest(call) -> None:
        lock_id = call.data["lock_id"]
        lock = coordinator._get_lock(lock_id)
        if lock is None:
            _LOGGER.error("delete_guest: lock_id %s not found", lock_id)
            return
        admin_acu_id = int(lock.get("adminAcuId") or 0)
        ok = await api_delete_guest(
            coordinator._session, coordinator.jwt, coordinator.des3_key,
            lock_id, call.data["user_acu_id"], admin_acu_id,
        )
        hass.bus.async_fire("lockly_guest_deleted", {
            "lock_id": lock_id,
            "user_acu_id": call.data["user_acu_id"],
            "success": ok,
        })

    async def handle_query_passwords(call) -> None:
        """Diagnostic: read the lock's credential list and report what it holds.

        Reports slot numbers and whether the host slot matches the cloud's copy.
        The passwords themselves are deliberately not logged or published.
        """
        lock_id = call.data["lock_id"]
        lock = coordinator._get_lock(lock_id)
        if lock is None:
            _LOGGER.error("query_passwords: lock_id %s not found", lock_id)
            return
        # Forget any cached answer so the service always re-reads the lock.
        coordinator._host_passwords.pop(lock_id, None)
        nonce = await coordinator._refresh_nonce(lock)
        host_pwd = await coordinator._resolve_host_password(lock, nonce)
        hass.bus.async_fire("lockly_passwords_queried", {
            "lock_id": lock_id,
            "lock_name": lock.get("na") or lock.get("blename") or lock_id,
            "host_slot_found": host_pwd is not None,
            "matches_cloud_hc": (
                host_pwd == str(lock.get("hc") or "") if host_pwd is not None else None
            ),
        })

    async def handle_read_access_log(call) -> None:
        """Read a lock's access log on demand.

        This is the manual counterpart to the single read at startup.  It wakes
        the lock, so the lock will beep if its BLE sound is on — which is why it
        is not on a timer.
        """
        lock_id = call.data["lock_id"]
        lock = coordinator._get_lock(lock_id)
        if lock is None:
            _LOGGER.error("read_access_log: lock_id %s not found", lock_id)
            return
        await coordinator._maybe_read_lock_log(lock, force=True)

    hass.services.async_register(DOMAIN, "read_access_log", handle_read_access_log, schema=_LIST_GUESTS_SCHEMA)
    hass.services.async_register(DOMAIN, "query_passwords", handle_query_passwords, schema=_LIST_GUESTS_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_LIST_GUESTS,  handle_list_guests,  schema=_LIST_GUESTS_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_ADD_GUEST,    handle_add_guest,    schema=_ADD_GUEST_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_DELETE_GUEST, handle_delete_guest, schema=_DELETE_GUEST_SCHEMA)
