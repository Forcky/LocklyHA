"""Config flow for Lockly integration."""
from __future__ import annotations

import logging

import aiohttp
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .api import api_get_devices, api_login
from .const import CONF_EMAIL, CONF_PASSWORD, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


async def _validate_credentials(hass: HomeAssistant, email: str, password: str) -> str | None:
    """Try to log in and return error key, or None on success."""
    try:
        async with aiohttp.ClientSession() as session:
            jwt = await api_login(session, email, password)
            if not jwt:
                return "invalid_auth"
            locks, _ = await api_get_devices(session, jwt, email)
            if not locks:
                return "no_devices"
    except Exception:
        _LOGGER.exception("Error validating Lockly credentials")
        return "cannot_connect"
    return None


class LocklyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the Lockly config flow."""

    VERSION = 1

    async def async_step_user(self, user_input: dict | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
            self._abort_if_unique_id_configured()

            error = await _validate_credentials(
                self.hass, user_input[CONF_EMAIL], user_input[CONF_PASSWORD]
            )
            if error:
                errors["base"] = error
            else:
                return self.async_create_entry(
                    title=user_input[CONF_EMAIL],
                    data={
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_USER_DATA_SCHEMA,
            errors=errors,
        )
