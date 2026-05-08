"""Lockly sensor entities."""
from __future__ import annotations

import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LocklyCoordinator
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# Voltage values are only available from a live senddata query (not cached status).
# Cached status only has LOW_BAT_BIT.  When low battery is flagged we report 10%;
# when the flag is clear we have no precise percentage to show, so we report None.
_LOW_BAT_PCT = 10


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: LocklyCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        LocklyBatterySensor(coordinator, lock["ID"]) for lock in coordinator.locks
    )


def _lock_display_name(lock_data: dict, lock_id: str) -> str:
    return lock_data.get("na") or lock_data.get("blename") or lock_id


class LocklyBatterySensor(CoordinatorEntity, SensorEntity):
    """Battery indicator for a Lockly lock.

    Reports 10 % when the lock's low-battery flag is set; None otherwise
    (the cloud cache does not expose a precise voltage).
    """

    _attr_has_entity_name = True
    _attr_name = "Battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = PERCENTAGE

    def __init__(self, coordinator: LocklyCoordinator, lock_id: str) -> None:
        super().__init__(coordinator)
        self._lock_id = lock_id
        lock_data = coordinator.data.get(lock_id, {})
        self._attr_unique_id = f"lockly_{lock_id}_battery"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock_id)},
            name=_lock_display_name(lock_data, lock_id),
            manufacturer="Lockly",
            model=lock_data.get("lockType") or "Smart Lock",
        )

    @property
    def _lock_data(self) -> dict:
        return self.coordinator.data.get(self._lock_id, {})

    @property
    def native_value(self) -> int | None:
        d = self._lock_data
        low = d.get("low_battery")
        if low is None:
            return None          # no data yet → unavailable
        return _LOW_BAT_PCT if low else 90  # 90 = proxy for "OK"

    @property
    def extra_state_attributes(self) -> dict:
        d = self._lock_data
        attrs: dict = {}
        low = d.get("low_battery")
        if low is not None:
            attrs["low_battery"] = low
        return attrs
