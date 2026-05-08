"""Lockly lock entity."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LocklyCoordinator
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: LocklyCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        LocklyLock(coordinator, lock["ID"]) for lock in coordinator.locks
    )


class LocklyLock(CoordinatorEntity, LockEntity):
    """Represents a Lockly smart lock."""

    _attr_has_entity_name = True
    _attr_name = None  # use device name as entity name

    def __init__(self, coordinator: LocklyCoordinator, lock_id: str) -> None:
        super().__init__(coordinator)
        self._lock_id = lock_id
        lock_data = coordinator.data.get(lock_id, {})
        self._attr_unique_id = f"lockly_{lock_id}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock_id)},
            name=lock_data.get("na") or lock_data.get("blename") or lock_id,
            manufacturer="Lockly",
            model=lock_data.get("lockType") or "Smart Lock",
        )

    @property
    def _lock_data(self) -> dict:
        return self.coordinator.data.get(self._lock_id, {})

    @property
    def is_locked(self) -> bool | None:
        if "is_locked" not in self._lock_data:
            return None
        return self._lock_data["is_locked"]

    @property
    def is_locking(self) -> bool:
        return False

    @property
    def is_unlocking(self) -> bool:
        return False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        d = self._lock_data
        attrs: dict[str, Any] = {}
        for key in ("firmware_version", "door_sensor_open", "auto_unlock_delay_s"):
            val = d.get(key)
            if val is not None:
                attrs[key] = val
        return attrs

    async def async_unlock(self, **kwargs: Any) -> None:
        await self.coordinator.async_unlock_lock(self._lock_id)

    async def async_lock(self, **kwargs: Any) -> None:
        await self.coordinator.async_lock_lock(self._lock_id)
