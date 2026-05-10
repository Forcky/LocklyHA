"""Lockly binary sensor entities."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import LocklyCoordinator
from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: LocklyCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        LocklyDoorSensor(coordinator, lock) for lock in coordinator.locks
    )


class LocklyDoorSensor(CoordinatorEntity, BinarySensorEntity):
    """Door sensor for a Lockly lock (wired or RF).

    Available only when the coordinator data confirms a door sensor is connected.
    State: True = door open, False = door closed.
    """

    _attr_has_entity_name = True
    _attr_name = "Door"
    _attr_device_class = BinarySensorDeviceClass.DOOR

    def __init__(self, coordinator: LocklyCoordinator, lock: dict) -> None:
        super().__init__(coordinator)
        lock_id = lock["ID"]
        self._lock_id = lock_id
        self._attr_unique_id = f"lockly_{lock_id}_door"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock_id)},
            name=lock.get("na") or lock.get("blename") or lock_id,
            manufacturer="Lockly",
            model=lock.get("lockType") or "Smart Lock",
        )

    @property
    def _lock_data(self) -> dict:
        return self.coordinator.data.get(self._lock_id, {})

    @property
    def available(self) -> bool:
        d = self._lock_data
        return bool(d.get("wired_door_sensor_connected")) or bool(d.get("rf_door_sensor_connected"))

    @property
    def is_on(self) -> bool | None:
        return self._lock_data.get("door_sensor_open")
