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
from .const import BATTERY_MAX_V, BATTERY_MIN_V, DOMAIN

_LOGGER = logging.getLogger(__name__)

# Sentinel percentages used when only the binary low/normal flag is available
# (cloud cache endpoint, or live query with battery_invalid=True).
_LOW_BAT_PCT = 10
_OK_BAT_PCT = 90


def _voltage_to_pct(raw: int) -> int:
    """Convert raw wakeup_voltage (10 mV units) to a clamped battery percentage.

    Voltage range for 4×AA: BATTERY_MIN_V (empty) to BATTERY_MAX_V (full).
    raw * 0.01 = volts  (raw is in units of 10 mV = 0.01 V)
    """
    volts = raw * 0.01
    pct = (volts - BATTERY_MIN_V) / (BATTERY_MAX_V - BATTERY_MIN_V) * 100
    return max(0, min(100, round(pct)))


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: LocklyCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for lock in coordinator.locks:
        entities.append(LocklyBatterySensor(coordinator, lock))
        entities.append(LocklyLastAccessSensor(coordinator, lock))
    async_add_entities(entities)


def _lock_display_name(lock_data: dict, lock_id: str) -> str:
    return lock_data.get("na") or lock_data.get("blename") or lock_id


class LocklyBatterySensor(CoordinatorEntity, SensorEntity):
    """Battery level for a Lockly lock.

    Uses the wakeup_voltage from the live BLE query (one-time at startup) for a
    real percentage.  Falls back to 10 % / 90 % sentinels when only the binary
    low-battery flag is available (cloud cache or invalid voltage reading).
    """

    _attr_has_entity_name = True
    _attr_name = "Battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = PERCENTAGE

    def __init__(self, coordinator: LocklyCoordinator, lock: dict) -> None:
        super().__init__(coordinator)
        lock_id = lock["ID"]
        self._lock_id = lock_id
        self._attr_unique_id = f"lockly_{lock_id}_battery"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock_id)},
            name=_lock_display_name(lock, lock_id),
            manufacturer="Lockly",
            model=lock.get("mod") or "Smart Lock",
        )

    @property
    def _lock_data(self) -> dict:
        return self.coordinator.data.get(self._lock_id, {})

    @property
    def native_value(self) -> int | None:
        d = self._lock_data

        # Real voltage — present after a live BLE query (startup or post-command).
        raw_v = d.get("wakeup_voltage")
        if raw_v is not None and not d.get("battery_invalid"):
            return _voltage_to_pct(raw_v)

        # Binary flag — from cloud cache (cachedstatus) or invalid voltage.
        low = d.get("low_battery")
        if low is None:
            return None  # no data yet → unavailable
        return _LOW_BAT_PCT if low else _OK_BAT_PCT

    @property
    def extra_state_attributes(self) -> dict:
        d = self._lock_data
        attrs: dict = {}
        raw_v = d.get("wakeup_voltage")
        if raw_v is not None:
            attrs["voltage"] = round(raw_v * 0.01, 2)
        low = d.get("low_battery")
        if low is not None:
            attrs["low_battery"] = low
        if d.get("battery_invalid"):
            attrs["battery_invalid"] = True
        return attrs


class LocklyLastAccessSensor(CoordinatorEntity, SensorEntity):
    """Shows who most recently accessed the lock and when."""

    _attr_has_entity_name = True
    _attr_name = "Last Access"
    _attr_icon = "mdi:account-clock"

    def __init__(self, coordinator: LocklyCoordinator, lock: dict) -> None:
        super().__init__(coordinator)
        lock_id = lock["ID"]
        self._lock_id = lock_id
        self._attr_unique_id = f"lockly_{lock_id}_last_access"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock_id)},
            name=_lock_display_name(lock, lock_id),
            manufacturer="Lockly",
            model=lock.get("mod") or "Smart Lock",
        )

    @property
    def _lock_data(self) -> dict:
        return self.coordinator.data.get(self._lock_id, {})

    @property
    def native_value(self) -> str | None:
        """Who last opened the lock.

        The coordinator resolves the credential slot to a name where it can.
        When it cannot, report the slot rather than "Unknown" — a slot number is
        at least actionable, and the old behaviour reported every keypad and
        fingerprint entry as Unknown because those carry no name in the event.
        """
        event = self._lock_data.get("last_access_event")
        if not event:
            return None
        operator = event.get("operator")
        if operator:
            return operator
        pid = event.get("pid")
        if pid is None:
            return "Unknown"
        if event.get("operator_candidates"):
            return f"Slot {pid} (ambiguous)"
        return f"Slot {pid}"

    @property
    def extra_state_attributes(self) -> dict:
        event = self._lock_data.get("last_access_event")
        if not event:
            return {}
        attrs: dict = {
            # Raw numeric code from the lock; the label mapping is not yet ported.
            "event_code": event.get("co"),
            "credential_slot": event.get("pid"),
            "timestamp": event.get("tm"),
            "event_id": event.get("id"),
        }
        candidates = event.get("operator_candidates")
        if candidates:
            # Slot numbers are namespaced per credential type, so a slot can map
            # to more than one user and the event does not say which type it was.
            attrs["operator_candidates"] = candidates
        return attrs
