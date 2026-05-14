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
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    api_cached_status,
    api_get_devices,
    api_get_lock_history,
    api_add_guest,
    api_delete_guest,
    api_list_guests,
    api_lock,
    api_login,
    api_query_lock_status,
    api_unlock,
)
from .mqtt import LocklyMQTTManager
from .const import (
    CONF_EMAIL,
    CONF_PASSWORD,
    DOMAIN,
    HISTORY_INTERVAL_SECONDS,
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
        for svc in (SERVICE_LIST_GUESTS, SERVICE_ADD_GUEST, SERVICE_DELETE_GUEST):
            hass.services.async_remove(DOMAIN, svc)
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
        # Lock IDs that still need a one-time live query for their initial state.
        self._pending_live_init: set[str] = set()
        # Access log polling state.
        self._history_cursors: dict[str, int] = {}  # lock_id -> LAST_EVENT_SYNC_TIME ms
        self._history_cancel: list = []

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
        self._cache_supported = True
        self._pending_live_init = {lock["ID"] for lock in self.locks}
        _LOGGER.info("Lockly: authenticated, found %d lock(s)", len(self.locks))

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

            # One-time live query for initial state when cache is unavailable.
            # Discard from the pending set unconditionally so a failed query is
            # not retried on the next poll (which would cause repeated BLE sends
            # and beeping on hubs where cachedstatus is unsupported).
            if status is None and lock_id in self._pending_live_init:
                self._pending_live_init.discard(lock_id)
                status = await api_query_lock_status(
                    self._session, self.jwt, self.email, self.des3_key, lock
                )

            if status:
                result[lock_id] = {**lock, **status}
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

    async def async_unlock_lock(self, lock_id: str) -> bool:
        lock = self._get_lock(lock_id)
        if lock is None:
            return False
        ok = await api_unlock(self._session, self.jwt, self.email, self.des3_key, lock)
        if ok:
            self._set_optimistic_lock_state(lock_id, is_locked=False)
        return ok

    async def async_lock_lock(self, lock_id: str) -> bool:
        lock = self._get_lock(lock_id)
        if lock is None:
            return False
        ok = await api_lock(self._session, self.jwt, self.email, self.des3_key, lock)
        if ok:
            self._set_optimistic_lock_state(lock_id, is_locked=True)
        return ok

    def _set_optimistic_lock_state(self, lock_id: str, is_locked: bool) -> None:
        if self.data and lock_id in self.data:
            updated = {**self.data, lock_id: {**self.data[lock_id], "is_locked": is_locked}}
            self.async_set_updated_data(updated)

    def _get_lock(self, lock_id: str) -> dict | None:
        return next((l for l in self.locks if l["ID"] == lock_id), None)

    def async_start_history_polling(self) -> None:
        """Register the 5-minute access log poll timer. Call after platform setup."""
        cancel = async_track_time_interval(
            self.hass,
            self._async_poll_history,
            timedelta(seconds=HISTORY_INTERVAL_SECONDS),
        )
        self._history_cancel.append(cancel)

    async def _async_poll_history(self, _now=None) -> None:
        if not self.jwt or self.des3_key is None or not self.locks:
            return
        await self._ensure_session()
        for lock in self.locks:
            lock_id = lock["ID"]
            since_ms = self._history_cursors.get(lock_id, 0)
            result = await api_get_lock_history(
                self._session, self.jwt, self.des3_key, self.email, lock_id, since_ms
            )
            if result is None:
                continue
            events, new_cursor = result
            if new_cursor > since_ms:
                self._history_cursors[lock_id] = new_cursor
            for event in events:
                _LOGGER.debug("lockly history event raw: %s", event)
                self.hass.bus.async_fire(
                    "lockly_lock_event",
                    {
                        "lock_id": lock_id,
                        "lock_name": lock.get("na") or lock.get("blename") or lock_id,
                        "event_type": event.get("co") or "UNKNOWN",
                        "user_id": str(event.get("pid") or ""),
                        "user_name": event.get("na") or "",
                        "timestamp": event.get("tm") or 0,
                        "event_id": event.get("id") or 0,
                    },
                )
            # Update last_access_event on coordinator data so the sensor reflects it.
            # Use the event with the largest tm value (getlkhist returns oldest-first).
            if events and self.data and lock_id in self.data:
                latest = max(events, key=lambda e: e.get("tm", 0))
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

    hass.services.async_register(DOMAIN, SERVICE_LIST_GUESTS,  handle_list_guests,  schema=_LIST_GUESTS_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_ADD_GUEST,    handle_add_guest,    schema=_ADD_GUEST_SCHEMA)
    hass.services.async_register(DOMAIN, SERVICE_DELETE_GUEST, handle_delete_guest, schema=_DELETE_GUEST_SCHEMA)
