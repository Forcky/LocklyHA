# Lockly Home Assistant Integration

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![HA Version](https://img.shields.io/badge/Home%20Assistant-2024.1%2B-blue.svg)](https://www.home-assistant.io/)
[![GitHub Release](https://img.shields.io/github/v/release/Forcky/LocklyHA)](https://github.com/Forcky/LocklyHA/releases)
[![Version](https://img.shields.io/badge/version-0.7.10-blue.svg)](https://github.com/Forcky/LocklyHA/releases/tag/v0.7.10)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Control and monitor your **Lockly smart locks** from Home Assistant. This integration communicates with the Lockly cloud API using the same protocol as the official Lockly mobile app.

> **Unofficial integration.** Not affiliated with or endorsed by Lockly Security Inc.

---

## Features

| Feature | Status |
|---|---|
| Unlock from HA | ✅ Verified on PGD628FN + PGH220 hub |
| Lock from HA | 🚧 Implemented; hard to verify on auto-locking locks |
| In-progress state while a command runs | ✅ From 0.7.7 |
| Commands over MQTT when senddata is refused | ✅ Verified on PGD728FN + PGH260 hub (cod=930 accounts) |
| Native Auto-Lock (Automation), set on the lock | ✅ From 0.7.8 on PGK728WRHK; MQTT-only |
| Hubless WiFi-native locks | ✅ Verified from 0.7.4 on two PGK728WRHK (Lockly Visage), firmware 1.14.31 and 3.00.24 |
| Lock state (locked / unlocked) | ✅ At startup and after HA commands |
| Battery low warning | ✅ |
| Door sensor state (if fitted) | ✅ Verified open and closed on a wired sensor; on-demand refresh service from 0.7.10 |
| Last access / who entered | ✅ Read from the lock; names resolve unless a slot is shared |
| Guest PIN management (add / remove / list) | 🚧 In progress |
| Real-time push of external (keypad / app) lock changes | ✅ On WiFi-native locks from 0.7.6 · ⛔ On hub locks — needs an FCM token HA cannot obtain |
| Multiple locks per account | ✅ |
| Silent polling — lock does not beep during polls | ⚠️ Needs hub firmware ≥ build 422 |
| Config flow UI | ✅ |
| HACS installable | ✅ |

---

## Prerequisites

- Home Assistant 2024.1 or later
- A Lockly account, and a lock that reaches the internet — either behind a PGH-series hub, or a WiFi-native model that connects on its own
- Your Lockly app email and password

> Locks that connect only over Bluetooth are **not** supported. The integration uses the Lockly cloud API, so the lock has to be reachable from it: through a hub, or by its own WiFi. Hubless WiFi-native locks are supported from 0.7.4 and use a different transport — see [Known Limitations](#known-limitations).

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

### Native Auto-Lock (Automation)

Lockly's Automation mode is executed by the lock itself: the deadbolt stays
retracted while the door is open and throws the moment the lock's magnetic
sensor detects the door closing. Home Assistant does not poll a door sensor or
run a timer to make this happen — it only writes the setting.

| Service | Required fields | Optional fields |
|---|---|---|
| `lockly.enable_native_auto_lock` | `lock_id` | — |
| `lockly.disable_native_auto_lock` | `lock_id` | — |

Results are returned as the bus events `lockly_native_auto_lock_enabled` and
`lockly_native_auto_lock_disabled`, each carrying `lock_id` and `success`.

> **Two limits worth knowing.** This path is MQTT-only, so a hub-relayed lock
> will refuse it and log that it could not get a nonce. It is also gated to
> hardware the behaviour has been verified on — currently PGK728WRHK (type 105)
> — and other models are declined rather than guessed at.

Enabling while the door is already closed and unlocked does **not** lock it.
Automation acts on the next door-close transition, not on the current state.

### Refresh door state on demand

The door sensor updates when the lock is commanded and, on WiFi-native locks,
when the lock pushes a state callback. Neither covers a door that opens and
closes without the lock being touched, and at least one model does not push
magnet state at all. This service asks the lock directly.

| Service | Required fields |
|---|---|
| `lockly.refresh_door_state` | `lock_id` |

The answer lands on the door entity and on a `lockly_door_state_refreshed`
event carrying `lock_id` and `door_open`, so an automation can wait for the
reading it asked for. `door_open: null` means the lock did not answer, which is
not the same as a closed door.

> **This wakes the lock.** It sends a real Bluetooth status frame, so the lock
> may chirp — call it when you need a current reading, not on a timer. It is
> MQTT-only: a hub-relayed lock cannot answer it.

---

## Entities

Each lock creates four entities:

### Lock entity

- **State**: `locked` or `unlocked`, and `locking` / `unlocking` while a command
  is in flight (from 0.7.7)
- **Services**: `lock.lock`, `lock.unlock`
- **Attributes**:
  - `door_sensor_open` — door circuit state, if a sensor is fitted. `true` also occurs on locks with no sensor; see [Door sensor](#door-sensor)
  - `firmware_version` — lock firmware string (available from live query)
  - `auto_unlock_delay_s` — configured auto-lock delay in seconds (available from live query)

> **How long `locking` / `unlocking` lasts depends on your hardware.** It covers
> the whole command, so on a hub-attached lock it is roughly one `senddata`
> round trip. On a hubless WiFi-native lock it spans two transports — `senddata`
> being refused, then the command going over the broker — so it is visibly
> longer. That is the entity reporting honestly how long the command takes, not
> a stall. It clears even if the command fails.

### Battery sensor

- **State**: `10` (%) when the lock reports low battery, `90` (%) otherwise
- **Device class**: `battery`
- **Attributes**:
  - `low_battery` — raw boolean from the cloud or live query

> **Battery percentage note:** The Lockly cloud cache only exposes a binary low/normal flag, not a precise voltage. The 10 % / 90 % values are representative sentinels, not real measurements.

### Door sensor

- **State**: `open` or `closed`
- **Device class**: `door`
- **Availability**: `unavailable` until the lock has reported a **closed** door at
  least once

The availability rule is not arbitrary. The lock reports a door *circuit*, not a
door sensor: a shut door completes the circuit, an open door breaks it — and a
lock with no sensor fitted is a broken circuit permanently. So "open" is
ambiguous between a genuinely open door and no sensor at all, while "closed" can
only come from a real sensor. The entity therefore appears the first time a lock
reports closed, and stays available from then on.

In practice it appears on the first poll for any lock whose door is shut. If it
stays `unavailable`, shut the door and trigger a refresh — restart HA, or send
any lock command. The learned state is held in memory, so it is re-learned after
each restart. See [Known Limitations](#known-limitations).

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

### MQTT real-time push (🚧 depends on your hub)

The integration connects to the Lockly MQTT broker at startup and listens on its
own client topic for state callbacks. Whether anything arrives depends on your
hub being connected to that channel.

On the hardware this was developed against, a PGH220 on firmware build 417, the
broker answers commands with `3005 device is offline` — the hub is not on the
channel, so no push arrives and state behaves as described above. Newer hubs
appear to be connected to it, since the official app uses this channel to
control locks over WiFi.

Earlier versions declared this impossible. That was wrong: the integration had
been subscribing to `server`, which is a publish-only topic that no client reads
from, and the broker was correctly refusing it. Replies and callbacks arrive on
`client/<client_id>` instead.

The broker grants this subscription, so the channel itself is open:

```
Lockly MQTT connected, subscribing to 'client/…'
Lockly MQTT subscribed to 'client/…' at qos=[0]
```

That is verified working, including on the build-417 hub. But listening is not
the same as being sent external state, and two flows share this channel — only
one of which reaches Home Assistant:

- **Command confirmation works.** The fresh state that comes back right after an
  HA-initiated lock or unlock is routed to our own `client/<client_id>` topic.
  Verified on a `PGD728FN` behind a `PGH260` hub: lock state is correct
  immediately after every command.
- **Unsolicited push depends on the lock, and 0.7.6 fixed our half of it.** On a
  hub-attached lock it still does not arrive: the server pushes external changes
  only to a client id registered through Lockly's Firebase/AIPN service, which
  needs a real FCM token from a genuine app install (`JobService.u()` in the
  decompiled app), and Home Assistant's ephemeral client id is never registered.

  WiFi-native locks are different — they send `deviceStateCallback` messages to
  our own client topic without any of that, and until 0.7.6 this integration
  discarded every one of them. It looked for the item list at the root of the
  message, where it is actually under `payload`, and matched the uppercase
  `LOCKED_STATUS` key, where a Visage sends lowercase `lock` with the value
  `locked` or `unlocked`. Both shapes came from reading the app and neither had
  ever been checked against a live message. On these locks a keypad or app
  unlock now reaches Home Assistant. No `magnet` key has appeared in any
  captured callback, so the *door* sensor still only updates from a status
  query.

So state is accurate immediately after you act through HA, and otherwise stale
until the next HA command — or the next successful poll, on hubs new enough for
silent polling. A `SUBACK 0x80` refusal on the client topic is not fatal, since
the broker was observed delivering a message without granting a subscription, so
the connection is kept regardless.

### Authentication

Credentials (email and password) are stored in HA's config entry. The integration obtains a JWT at startup and automatically re-authenticates when it expires.

---

## Known Limitations

- **Bluetooth-only locks are not supported.** The integration talks to the Lockly cloud, so a lock it can never reach is out of scope. WiFi-native locks with no hub *are* supported — see below.
- **Hubless WiFi-native locks: commands work, `cod=930` in the log is expected.** Models such as the `PGK728WRHK` and `PGD728FG25` connect straight to WiFi with no hub to relay through, so their `hubid` is empty and the `senddata` endpoint refuses everything they send with `cod=930`. That is by design and not a fault: commands for these locks go over the MQTT transport instead, and from 0.7.4 they work. Verified on two `PGK728WRHK` (Lockly Visage) on firmware 1.14.31 and 3.00.24 — lock and unlock both succeed and the state change is confirmed back over the broker.

  What still does not work on them: `senddata`'s state and access-log queries, for the same reason, and `QueryPwd147` (`0x93`) returns `0xFA`, so the host credential is read from the cloud's copy rather than from the lock. Neither blocks locking or unlocking.
- **Unlock is verified from 0.5.0.** Two fields in the command frame were wrong: the `str3` hub flag was sent as `00` instead of `01`, and the credential slot was sent as `1` instead of `0` (the host credential lives in slot 0). Both had to be right at once, which is why this took so long to find. Confirmed against physical hardware — a PGD628FN on firmware 4.03.15 behind a PGH220 hub.
- **Commands fall back to MQTT when `senddata` fails, and this is verified.** If
  your logs are full of `cod=930` while the official Lockly app controls your
  locks normally, the app is reaching them over Lockly's MQTT broker rather than
  through `senddata`. The integration now does the same: when a lock or unlock
  is refused, it fetches a fresh nonce, reads the host password from the lock,
  and sends the command over the broker, all on that transport.

  Confirmed working from 0.7.1 by a user whose `senddata` calls all return
  `cod=930` — locking and unlocking both succeed. That account is on a
  `PGD728FN` behind a `PGH260` hub.

  Reading the host password from the lock is not yet modelled for every lock
  type — a `PGD728FN` credential frame has a layout this parser does not fully
  decode, so on that model the command is built from the cloud's copy of the
  password instead, which works. The earlier releases logged a traceback here;
  that is fixed and the fallback is silent.

  Note what is *not* yet routed this way: the periodic status query and the
  access log still go through `senddata`, so on an affected account lock state
  can be stale even while commands work. That is the next thing to move across.
- **WiFi-native locks: the command frame was corrected in 0.7.4, and is confirmed.**
  Locks with no hub at all reached the broker and were then refused by the lock
  itself with `0xFF`, "wrong password". The credential was never the problem —
  the frame was. The `0x52` command these locks use carries a two-byte
  access-user field where the integration sent one, ends in the phone's clock as
  an 8-byte value rather than the lock's stored nonce, and is wrapped with
  encryption type `0xB` rather than `5`. The first of those left every later
  field a byte out of place, which is enough on its own to fail a credential
  check that would otherwise pass. All three shipped together; sending one
  without the others only moves the corruption.

  Diagnosed from `NewUnlockCmd.getData` rather than from a capture, by the
  reporter of [issue #3](https://github.com/Forcky/LocklyHA/issues/3), and
  confirmed by them on two locks within hours of the release.
- **Real-time push of external changes: depends on the lock, and this was wrong
  until 0.7.6.** State arriving right after an HA-initiated lock or unlock has
  always been correct — that reply is routed to our own MQTT client topic.
  Beyond that, earlier versions said flatly that outside changes could never
  reach Home Assistant, on the grounds that the server only pushes to a client
  id registered through Lockly's Firebase/AIPN service, which needs an FCM token
  from a genuine app install. The registration part is still true, and it is
  still why hub-attached locks do not push.

  But WiFi-native locks do send `deviceStateCallback` messages to our own client
  topic, and this integration was throwing them away: it looked for the item
  list at the root of the message where it actually sits under `payload`, and
  matched an uppercase `LOCKED_STATUS` key where a Visage sends a lowercase
  `lock` with the value `locked` or `unlocked`. Both came from reading the app
  rather than a capture, and neither had been checked against a live message.
  0.7.6 reads both shapes, so on these locks an unlock at the keypad or in the
  Lockly app now reaches Home Assistant.

  Door state does *not* arrive this way. No `magnet` key has been seen in any
  captured callback from these locks, so the door sensor still only updates from
  a status query. Reported and captured on
  [#5](https://github.com/Forcky/LocklyHA/pull/5).
- **Silent polling requires hub firmware build ≥ 422** (for major-version-2 hubs). On older firmware `lock/cachedstatus/get` returns `cod=900` and state only updates at startup and after HA commands. Note that Lockly does not necessarily offer an upgrade: a PGH220 on `2.2.04.17` (build 417) reports itself up to date, five builds short of the requirement.

- **Door sensor state is verified, but sensor _presence_ cannot be read from the lock.** Bit 0 of the status byte is the door circuit: `0` = closed, `1` = open. A closed door completes the circuit and an open door breaks it — but a lock with no sensor fitted is an open circuit permanently, so it reads `1` too. That makes `1` ambiguous between "door open" and "no sensor fitted", and this ACK carries no separate presence flag. (The hub's `lock/cachedstatus/get` response does have one, at bit 1, but that endpoint needs newer hub firmware — see above.)

  The integration resolves the ambiguity by observation instead. A `0` can only come from a real sensor, so the first time a lock reports a closed door its `Door` entity becomes available and stays available. A lock that has never reported closed keeps the entity `unavailable` — the honest answer, rather than showing a permanently-open door that may not exist. In practice the entity appears on the first poll for any lock whose door is shut. If it stays `unavailable`, shut the door and trigger a refresh (restart HA, or send any lock command). One closed reading is enough, though it is held in memory only and re-learned after each restart.

  Confirmed by physically opening a sensor-equipped door and watching the bit flip. Two earlier readings of this bit were wrong — first as "sensor connected", then as its inverse — and each fitted every sample available at the time, because those samples all happened to have the sensor-equipped doors shut. Four locks agreeing is not evidence when all four share a confound.
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
