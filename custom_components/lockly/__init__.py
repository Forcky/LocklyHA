"""Lockly smart lock Home Assistant integration."""
from __future__ import annotations

import logging
from datetime import timedelta

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import api_cached_status, api_get_devices, api_lock, api_login, api_unlock
from .const import CONF_EMAIL, CONF_PASSWORD, DOMAIN, SCAN_INTERVAL_SECONDS

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["lock", "sensor"]


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
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        coordinator: LocklyCoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_shutdown()
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
        _LOGGER.info("Lockly: authenticated, found %d lock(s)", len(self.locks))

    async def _async_update_data(self) -> dict:
        await self._ensure_session()

        if not self.jwt or self.des3_key is None or not self.locks:
            await self._authenticate()

        result: dict = {}
        any_ok = False

        for lock in self.locks:
            lock_id = lock["ID"]
            # Use cloud cache — no BLE command sent, lock does not beep
            status = await api_cached_status(
                self._session, self.jwt, self.des3_key, self.email, lock
            )
            if status:
                result[lock_id] = {**lock, **status}
                any_ok = True
            elif self.data and lock_id in self.data:
                result[lock_id] = self.data[lock_id]
            else:
                result[lock_id] = dict(lock)  # static fields only; no live status

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
            await self.async_request_refresh()
        return ok

    async def async_lock_lock(self, lock_id: str) -> bool:
        lock = self._get_lock(lock_id)
        if lock is None:
            return False
        ok = await api_lock(self._session, self.jwt, self.email, self.des3_key, lock)
        if ok:
            await self.async_request_refresh()
        return ok

    def _get_lock(self, lock_id: str) -> dict | None:
        return next((l for l in self.locks if l["ID"] == lock_id), None)

    async def async_shutdown(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
