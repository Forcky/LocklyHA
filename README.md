# Lockly Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![HA Version](https://img.shields.io/badge/Home%20Assistant-2024.1%2B-blue.svg)](https://www.home-assistant.io/)
[![GitHub Release](https://img.shields.io/github/v/release/pforck/lockly-ha)](https://github.com/pforck/lockly-ha/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Control and monitor your **Lockly smart locks** from Home Assistant. This integration communicates with the Lockly cloud API using the same protocol as the official Lockly mobile app.

> **Unofficial integration.** Not affiliated with or endorsed by Lockly Security Inc.

---

## Features

| Feature | Status |
|---|---|
| Lock / Unlock from HA | ✅ |
| Real-time lock state (locked / unlocked) | ✅ |
| Battery low warning | ✅ |
| Door sensor state (if fitted) | ✅ |
| Multiple locks per account | ✅ |
| Silent polling — lock does not beep | ✅ |
| Config flow UI | ✅ |
| HACS installable | ✅ |

---

## Prerequisites

- Home Assistant 2024.1 or later
- A Lockly account with at least one PGH-series hub (cloud-connected lock)
- Your Lockly app email and password

> Locks that connect only over Bluetooth (no hub) are **not** supported. The integration uses the Lockly cloud API; a hub bridging the lock to the internet is required.

---

## Installation

### HACS (recommended)

1. Open HACS in your Home Assistant instance.
2. Go to **Integrations** → **⋮** → **Custom repositories**.
3. Add `https://github.com/pforck/lockly-ha` with category **Integration**.
4. Search for **Lockly** and click **Download**.
5. Restart Home Assistant.

### Manual

1. Download the [latest release](https://github.com/pforck/lockly-ha/releases) zip file.
2. Extract the `custom_components/lockly` folder into your HA configuration's `custom_components/` directory:
   ```
   config/
   └── custom_components/
       └── lockly/
           ├── __init__.py
           ├── api.py
           ├── config_flow.py
           ├── const.py
           ├── lock.py
           ├── manifest.json
           ├── sensor.py
           ├── strings.json
           └── translations/
               └── en.json
   ```
3. Restart Home Assistant.

---

## Configuration

1. Go to **Settings** → **Devices & Services** → **Add Integration**.
2. Search for **Lockly**.
3. Enter your Lockly account **email** and **password**.
4. Click **Submit**. The integration will log in, discover all locks on your account, and create entities automatically.

Each lock appears as a separate HA device.

---

## Entities

Each lock creates two entities:

### Lock entity
- **State**: `locked` or `unlocked`
- **Services**: `lock.lock`, `lock.unlock`
- **Attributes**:
  - `door_sensor_open` — state of the magnetic door sensor, if the lock has one fitted
  - `firmware_version` — lock firmware string (when available from a live query)
  - `auto_unlock_delay_s` — configured auto-lock delay in seconds (when available)

### Battery sensor
- **State**: `10` (%) when the lock reports low battery, `90` (%) otherwise
- **Device class**: `battery`
- **Attributes**:
  - `low_battery` — raw boolean from the cloud cache

> **Battery percentage note:** The Lockly cloud cache only exposes a binary low/normal flag, not a precise voltage. The 10 % / 90 % values are representative sentinels, not real measurements. A real percentage (derived from the battery voltage) is only available from a live BLE-over-hub query, which causes the lock to beep — so it is not used for routine polling.

---

## How It Works

### Polling (silent)

The integration polls the Lockly cloud cache endpoint (`lock/cachedstatus/get`) every 30 seconds. This endpoint returns the last known state that the Lockly hub uploaded — **no BLE command is ever sent to the physical lock during polling**, so the lock does not beep.

### Lock / Unlock actions

When you lock or unlock from HA, the integration sends a BLE command through the Lockly cloud and hub to the physical lock via the `senddata` endpoint. The lock will beep once to acknowledge the command. The state is then refreshed from the cloud cache.

### Authentication

Credentials (email and password) are stored in HA's config entry. The integration obtains a short-lived JWT at startup and automatically re-authenticates when it expires.

---

## Known Limitations

- **Bluetooth-only locks** (without a PGH hub) are not supported.
- **Battery percentage** is approximate (binary low/normal flag only).
- **Lock command** (`lock.lock`) has been implemented but not extensively tested across all Lockly hardware generations. If it doesn't close your lock, please open an issue with your lock model.
- The Lockly API is undocumented and reverse-engineered. A firmware update by Lockly could break this integration. See [`docs/api.md`](docs/api.md) for the full protocol documentation.
- The RSA keys embedded in `api.py` are extracted from **Lockly app version 3.2.9**. If Lockly rotates the keys in a later app release, the integration will stop working until updated.

---

## Troubleshooting

**Integration shows "cannot_connect"**
- Check that your Lockly hub is online in the official app.
- Verify your HA instance has outbound HTTPS access to `apiserv03c.lockly.com`.

**Integration shows "invalid_auth"**
- Ensure you're using your Lockly **app** email and password (not a Google/Apple SSO account).
- Try logging out and back in to the Lockly app to verify credentials.

**Locks show as unavailable after setup**
- The cloud cache may take up to 60 seconds to warm up after a hub reconnect. Wait and then reload the integration.

**Unlock works but lock does not close the door**
- Some older Lockly hardware generations may use a different BLE command for locking. Open an issue with your lock's BLE name (shown in the Lockly app) so support can be added.

**Enabling debug logs**

Add this to your `configuration.yaml`:

```yaml
logger:
  default: warning
  logs:
    custom_components.lockly: debug
```

---

## Contributing

Pull requests welcome. Please:
- Open an issue first for significant changes.
- Include your lock model and hub model if reporting a device-specific bug.
- See [`docs/api.md`](docs/api.md) for the full API protocol — useful background if you're extending the integration.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

This integration is not affiliated with, endorsed by, or supported by Lockly Security Inc. Use at your own risk. The integration was developed by reverse-engineering the Lockly Android app (version 3.2.9) for personal home-automation purposes.
