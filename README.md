# Lockly Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![HA Version](https://img.shields.io/badge/Home%20Assistant-2024.1%2B-blue.svg)](https://www.home-assistant.io/)
[![GitHub Release](https://img.shields.io/github/v/release/Forcky/LocklyHA)](https://github.com/Forcky/LocklyHA/releases)
[![Version](https://img.shields.io/badge/version-0.5.0-blue.svg)](https://github.com/Forcky/LocklyHA/releases/tag/v0.5.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Control and monitor your **Lockly smart locks** from Home Assistant. This integration communicates with the Lockly cloud API using the same protocol as the official Lockly mobile app.

> **Unofficial integration.** Not affiliated with or endorsed by Lockly Security Inc.

---

## Features

| Feature | Status |
|---|---|
| Unlock from HA | ✅ Verified on PGD628FN + PGH220 hub |
| Lock from HA | 🚧 Implemented; hard to verify on auto-locking locks |
| Lock state (locked / unlocked) | ✅ At startup and after HA commands |
| Battery low warning | ✅ |
| Door sensor state (if fitted) | 🚧 In progress |
| Last access / who entered | 🚧 In progress |
| Guest PIN management (add / remove / list) | 🚧 In progress |
| Real-time MQTT push (no-poll state updates) | ❌ Broker needs client-certificate auth — see Known Limitations |
| Multiple locks per account | ✅ |
| Silent polling — lock does not beep during polls | ⚠️ Needs hub firmware ≥ build 422 |
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
3. Add `https://github.com/Forcky/LocklyHA` with category **Integration**.
4. Search for **Lockly** and click **Download**.
5. Restart Home Assistant.

### Manual

1. Download the [latest release](https://github.com/Forcky/LocklyHA/releases) zip file.
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
           ├── mqtt.py
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

## Services

### Guest PIN management

Three HA services are available for managing time-limited guest PIN codes. Call them from **Developer Tools → Services** or from automations.

> **Status: 🚧 In progress** — services are implemented but PIN activation on lock hardware is unverified. See [Known Limitations](#known-limitations).

| Service | Required fields | Optional fields |
|---|---|---|
| `lockly.list_guests` | `lock_id` | — |
| `lockly.add_guest` | `lock_id`, `name`, `passcode` (4–8 digits) | `duration_hours` (default 24) **or** `start_time` + `end_time` |
| `lockly.delete_guest` | `lock_id`, `user_acu_id` | — |

Results are returned as HA bus events: `lockly_guest_list`, `lockly_guest_added`, `lockly_guest_deleted`. Listen for these in **Developer Tools → Events**.

`lock_id` is the device UUID (visible on the lock's device page in HA under *Identifiers*).

---

## Entities

Each lock creates four entities:

### Lock entity

- **State**: `locked` or `unlocked`
- **Services**: `lock.lock`, `lock.unlock`
- **Attributes**:
  - `door_sensor_open` — state of the magnetic door sensor, if the lock has one fitted
  - `firmware_version` — lock firmware string (available from live query)
  - `auto_unlock_delay_s` — configured auto-lock delay in seconds (available from live query)

### Battery sensor

- **State**: `10` (%) when the lock reports low battery, `90` (%) otherwise
- **Device class**: `battery`
- **Attributes**:
  - `low_battery` — raw boolean from the cloud or live query

> **Battery percentage note:** The Lockly cloud cache only exposes a binary low/normal flag, not a precise voltage. The 10 % / 90 % values are representative sentinels, not real measurements.

---

## How It Works

### Startup

When the integration loads, it authenticates with the Lockly cloud and retrieves the full lock list. It then attempts one silent cloud-cache poll per lock. If that fails (e.g. hub firmware is too old), it sends one live BLE query per lock to get the initial state. This may cause a brief **one-time beep** on each lock at startup.

### Polling (silent, every 30 seconds)

The integration polls the Lockly cloud cache endpoint (`lock/cachedstatus/get`) every 30 seconds. This endpoint returns the last known state the hub uploaded to the cloud — **no BLE command is ever sent to the physical lock during polling**, so the lock does not beep.

#### Hub firmware requirement for silent polling

Silent polling requires hub firmware with a sufficiently recent build number:

| Hub major version | Minimum build |
|---|---|
| 2.x | 422 (e.g. `2.2.04.22`) |
| 4.x | 401 |
| 6.x | 503 |

If the hub firmware is older than these minimums, the server returns an error and the integration switches to "no-poll" mode: state is preserved from the last successful query and only updates when a lock/unlock command is sent through HA. **No periodic BLE commands are ever sent** — the lock will not beep on a timer regardless of hub firmware version.

To check your hub firmware, look in the Lockly app under Hub settings, or check the HA logs for a line like:
```
Lockly: cachedstatus unsupported for this hub (hub firmware too old) — state will only update after HA commands
```

### Lock / Unlock actions

When you lock or unlock from HA, the integration sends a BLE command through the Lockly cloud and hub to the physical lock. The lock will beep once to acknowledge the command. The lock state in HA updates immediately (optimistically) without waiting for the next poll cycle.

### Access log polling (every 5 minutes)

The integration polls `getlkhist` every 5 minutes for each lock and fires a `lockly_lock_event` HA bus event for each new entry. The event includes `event_type`, `user_name`, `timestamp`, and `event_id`. The **Last Access** sensor on each lock device shows the most recent entry's user name and event details.

> **Status: 🚧 In progress** — event field names have been verified against the APK, but live hardware testing is still required.

### MQTT real-time push (🚧 in progress)

At startup the integration connects to the Lockly cloud MQTT broker using the same JWT used for REST API calls. When the lock state changes (via the official app, keypad, or fingerprint), the broker delivers a push message that updates HA instantly — without waiting for the next 30-second poll.

If the MQTT connection is refused, the integration logs a warning and continues in polling-only mode. No functionality is lost; state updates simply revert to the 30-second interval.

### Authentication

Credentials (email and password) are stored in HA's config entry. The integration obtains a JWT at startup and automatically re-authenticates when it expires.

---

## Known Limitations

- **Locks with no PGH hub are not supported.** This covers both Bluetooth-only locks and WiFi-native models such as the `PGD728FG25`, which connect straight to WiFi. The `senddata` endpoint relays commands through a hub, so with an empty `hubid` the cloud returns `cod=930` for both state and commands. The integration now detects this and says so rather than reporting a bare error code. Supporting these locks needs a different API path (tracked in issue #2).
- **Unlock is verified from 0.5.0.** Two fields in the command frame were wrong: the `str3` hub flag was sent as `00` instead of `01`, and the credential slot was sent as `1` instead of `0` (the host credential lives in slot 0). Both had to be right at once, which is why this took so long to find. Confirmed against physical hardware — a PGD628FN on firmware 4.03.15 behind a PGH220 hub.
- **Silent polling requires hub firmware build ≥ 422** (for major-version-2 hubs). On older firmware `lock/cachedstatus/get` returns `cod=900` and state only updates at startup and after HA commands. Note that Lockly does not necessarily offer an upgrade: a PGH220 on `2.2.04.17` (build 417) reports itself up to date, five builds short of the requirement.
- **Real-time MQTT push does not work yet.** The broker requires **client-certificate authentication**: `MqttSSLSocketFactory` in the app loads a CA, a client certificate and a client private key into a `KeyManagerFactory` over TLSv1.2. Connecting without a client certificate is refused (`rc=5`), or accepted and then denied at subscribe time (SUBACK `0x80`). Until this is implemented, state falls back to polling. See [`docs/api.md`](docs/api.md) §17, which also notes a possible HTTP alternative (`v1/proto/handler`).
- **Battery percentage is approximate** (binary low/normal flag only).
- **Guest PIN activation is unverified**: `lockly.add_guest` creates the guest record on the Lockly cloud. Whether the PIN is automatically pushed to the lock hardware is not yet confirmed. If the PIN does not work physically, open an issue.
- **`lock.lock` is implemented but unverified.** It differs from unlock by a single byte, and the app confirms these locks support an explicit lock command (`isSupportNewLock` covers PGD628FN). It is genuinely hard to observe on a lock with `autoLock` set, since the bolt throws itself within seconds either way. Please report whether it works on your model.
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

**Lock state does not update when physically used**
- This is expected when your hub firmware is below the silent-polling minimum. State updates only when commanded through HA or at the next restart.
- To get background state sync, update your hub firmware via the Lockly app to version `2.x.04.22` or later (for PGH220-series hubs).

**Locks beep every 30 seconds**
- This should not happen with the current version. If it does, check you are running the latest release and reload the integration.

**Unlock works but lock does not close the door**
- Some older Lockly hardware generations may use a different BLE command for locking. Open an issue with your lock's BLE name (shown in the Lockly app) so support can be added.

**Last Access sensor shows "Unknown"**
- Normal for anonymous keypad entries (no named user assigned to that PIN in the Lockly app). The sensor will show a name once a named user is added in the app.

**`lockly_lock_event` bus events never fire**
- Access log polling runs every 5 minutes. Wait at least 5 minutes after manually operating the lock.
- Check HA logs for `getlkhist failed: cod=` lines with debug logging enabled.

**MQTT shows "connection refused" in logs**
- The MQTT username format or broker address may differ from what was extracted from the APK. Enable debug logging to see the exact error code. The integration continues working in poll-only mode regardless.

**`lockly.add_guest` succeeds but PIN does not work on the lock**
- The guest record was created on the server but the PIN may not have been pushed to the lock hardware. Open an issue with your lock model so the passcode activation step can be implemented.

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
- Read [`AGENTS.md`](AGENTS.md) for architecture notes and critical invariants before writing code.
- See [`docs/api.md`](docs/api.md) for the full API protocol — useful background if you're extending the integration.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

This integration is not affiliated with, endorsed by, or supported by Lockly Security Inc. Use at your own risk. The integration was developed by reverse-engineering the Lockly Android app (version 3.2.9) for personal home-automation purposes.
