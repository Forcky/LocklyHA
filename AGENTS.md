# Agent Guide — Lockly HA Integration

This file is for AI coding agents working on this repository. Read it before writing or modifying any code.

---

## What this project is

A Home Assistant custom integration that controls and monitors Lockly smart locks via the Lockly cloud API. The API is reverse-engineered from the Lockly Android app (v3.2.9). There is no official API or SDK.

---

## Repository layout

```
custom_components/lockly/
  __init__.py       # DataUpdateCoordinator, entry setup/teardown
  api.py            # All crypto + HTTP — the only file that talks to the internet
  config_flow.py    # UI config flow (email + password)
  const.py          # URL base, common body, SCAN_INTERVAL_SECONDS
  lock.py           # LockEntity — reads coordinator.data
  sensor.py         # BatterySensor — reads coordinator.data
  manifest.json     # HA integration manifest (pycryptodome dependency)
docs/
  api.md            # Full protocol reference (reverse-engineering findings)
lockly_apk_analysis/
  FINDINGS.md       # Reverse-engineering notes
  jadx_out/         # Decompiled "LOCKLY" app (locklyLiteAlpha 3.2.9)
  jadx_home_out/    # Decompiled "Lockly Home" app (locklyHomeGp 1.4.8)
  lockly_traffic.jsonl  # Captured live API traffic (read-only reference)
```

### Searching the decompiled apps

**There are two decompiled trees, not one.** Lockly ships two apps that talk to
the same API and differ mainly in UI and a few features. `jadx_home_out` is the
larger of the two (34k Java files against 30k), so it holds code the other does
not. Search both before concluding something is absent: a claim that an endpoint
"does not exist in the app" was posted to a GitHub issue after searching only
`jadx_out`, and the endpoint was in `PgConfig.java` in both.

Note the versions. Users report from newer builds than these, so an absent
feature may simply postdate the copy here.

**`data/config/PgConfig.java` is the authoritative endpoint list.** It holds every
base URL and the MQTT broker address. Read it before assuming which host serves
what — `apiserv03c/pgsmtlkv2/api/` is the lock API, while `apiserv04c` hosts
payments, messaging and push under separate paths.

**Whole-tree greps time out.** Both trees are far too large for an unscoped
`grep -r`, and a timeout looks identical to "no matches" if you are not careful.
Scope every search to a subdirectory (`sources/android/content/res/data` is
usually the right one) and wrap it in `timeout`. If a search returns nothing,
confirm it actually completed before treating that as evidence.

---

## Architecture

```
HA                 LocklyCoordinator            api.py                  Lockly Cloud
  |                       |                       |                          |
  | async_setup_entry      |                       |                          |
  |---------------------> |                       |                          |
  |                       | _authenticate()        |                          |
  |                       |----> api_login() ----->|--POST login ----------->|
  |                       |<-------- jwt ----------|<--Authorization header--|
  |                       |----> api_get_devices()->|--POST qrylknew -------->|
  |                       |<-- locks[], des3_key --|<-- dl[] + key ----------|
  |                       |                       |                          |
  | poll (30s)            |                       |                          |
  |---------------------> | _async_update_data()   |                          |
  |                       |----> api_cached_status()|--POST cachedstatus/get->|
  |                       |       (silent, no BLE) |<-- sts bitmap ----------|
  |                       |                       |                          |
  | lock.lock / lock.unlock|                      |                          |
  |---------------------> | async_lock_lock()      |                          |
  |                       |----> api_lock() ------>|--POST senddata -------->|--BLE-->lock
  |                       |<-- ok=True ------------|<-- ACK -----------------|
  |                       | _set_optimistic_lock_state()                      |
  |<-- state update ----  |                       |                          |
```

---

## Critical invariants — read before changing anything

### 1. `directive` field values are lowercase strings

The `senddata` request's `directive` field uses **`"unlock"`** and **`"lock"`** (lowercase), not `"U"`/`"L"` or `"UNLOCK"`/`"LOCK"`. These are defined as constants in `SendDataReq.java`:
```java
public static final String LOCK = "lock";
public static final String UNLOCK = "unlock";
```
Using any other value causes the server to accept the request (cod=200) but the hub/lock does nothing.

### 2. Never call `senddata` in a polling loop

`senddata` relays a BLE frame from the hub to the physical lock. The lock **beeps** when it receives a BLE frame. Calling `senddata` every 30 seconds (the poll interval) will make every lock in the house beep constantly.

- `api_query_lock_status()` — uses `senddata`. Only call it for initial state fetch at startup (once per lock) or if there is no other way to get state.
- `api_unlock()` / `api_lock()` — use `senddata`. Fine; lock/unlock commands beep by design.
- `api_cached_status()` — uses `lock/cachedstatus/get`. Silent; no BLE contact. Use this for polling.

The coordinator enforces this: after the one-time startup query, all polling goes through `cachedstatus` only.

### 2. `cachedstatus` requires hub firmware build ≥ 422

The `lock/cachedstatus/get` endpoint is only supported if the hub firmware version meets:
- Major version 2, build ≥ 422 (e.g. `2.2.04.22` or later)
- Major version 4, build ≥ 401
- Major version 6, build ≥ 503

Older hubs return `cod=900` ("System error"). This is NOT a request format problem. The server is simply rejecting the request because the hub firmware predates the cached-status feature.

When all locks return `cod=900`, the coordinator sets `self._cache_supported = False` and logs once at INFO level. Subsequent polls skip `cachedstatus` entirely. The coordinator re-enables the probe after each re-authentication (in case the hub was updated).

### 3. All post-auth API calls use DES3-encrypted `para`

Every endpoint except `login` and `refresh` puts its payload in a DES3/ECB-encrypted `para` field. The outer request body contains only `COMMON_BODY` fields plus `"para"`. Do not put endpoint-specific fields directly in the outer body — the server will return `cod=909`.

```python
req  = {"acct": email, "dv": lock_id, "hubid": hub_id}
para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
body = {**COMMON_BODY, "para": para}
```

The `des3_key` comes from `qrylknew` — it is RSA-decrypted from the `key` field then base64-decoded and truncated to 24 bytes.

### 4. JWT is in the response header, not the body

```python
jwt = resp.headers.get("Authorization", "")
if jwt.startswith("Bearer "):
    jwt = jwt[7:]
```

`api_login()` already handles this. Do not look for the token in the response JSON body.

### 5. Crypto imports must be at module level

`pycryptodome` loads a native library (`libgmp.so`, etc.) on first import. If the import happens inside an `async def` (inside the HA event loop), it triggers blocking `glob.iglob` / `os.scandir` calls, which HA will flag as event-loop violations. Always import at the top of `api.py`:

```python
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA
```

### 6. The live status query must stay bounded

The startup BLE query that seeds state when `cachedstatus` is unavailable is
tracked by `_live_init_attempts` (attempts so far) and `_live_init_retry_at`
(when a given-up lock may be probed again). On hubs where `cachedstatus` is
unsupported, every poll produces `status = None`, so an unbounded retry here
calls `senddata` on every 30-second poll and makes the lock beep constantly.
That regression has already shipped once.

Equally, do not swing to the other extreme. This was previously a single
attempt discarded unconditionally, and one transient NACK or hub timeout then
left a lock with no state, and its door sensor unavailable, until HA restarted.
A hub outage lasting five days was observed recovering on its own with nothing
asking.

The shape that satisfies both:

- up to `LIVE_INIT_MAX_ATTEMPTS` attempts, one per poll cycle, cleared on success
- one warning when they are exhausted, then quiet
- afterwards one probe per `LIVE_INIT_REARM_SECONDS`, silent on failure, info on
  recovery

Any change here must keep the wake rate low enough that a permanently
unreachable lock is not woken often, while still recovering on its own. Roughly
two wakes an hour is the current budget; the beeping regression was twelve.

### 7. Optimistic state updates after commands

When the hub firmware is too old for `cachedstatus`, polling returns no new state. After a lock or unlock command succeeds, the coordinator immediately updates `self.data` via `async_set_updated_data()` so HA entities reflect the new state without waiting for the next poll cycle.

Do not call `async_request_refresh()` after lock/unlock — that would trigger another (silent) poll cycle immediately, which is harmless but wasteful. The optimistic update is sufficient.

---

## The crypto stack

```
Login / qrylknew:
  plaintext_json → RSA-1024/NoPadding encrypt (pub key) → base64 → para

All other endpoints (senddata, cachedstatus, etc.):
  plaintext_json → DES3/ECB encrypt (PKCS7 padded, 8-byte blocks) → base64 → para

qrylknew response — DES3 key derivation:
  body["key"] → RSA-1024/NoPadding decrypt (priv key) → 32-char ASCII
              → base64.b64decode()[:24] → des3_key (bytes)

qrylknew response — lock list decryption:
  each dl[] entry → base64 decode → DES3/ECB decrypt → JSON (BackupLockBean)

BLE command encryption (inside senddata cmd field):
  master_code + uuid → derive_aes_key() → AES-128/ECB encrypt
  raw bytes → build_ble_frame() → hex string
```

The RSA keys are embedded in `api.py` as DER-encoded base64 constants extracted from `libkey.so` in APK 3.2.9. If Lockly releases an app update with new keys, all RSA operations will fail silently.

---

## Lock data fields

The `lock` dict (from `coordinator.locks`) contains decoded `BackupLockBean` JSON. Key fields used by the integration:

| Field | Example | Usage |
|---|---|---|
| `ID` | `"2d0023003030471333363838"` | Device UUID — lock identifier everywhere |
| `na` | `"Front Door"` | User-set display name |
| `blename` | `"LOCKLYAA009868"` | BLE advertisement name (fallback display name) |
| `mc` | `24860092` | Master code — AES key derivation and BLE frame content |
| `hc` | `"980798"` | Lock password (`BackupLockBean.lockPwd`, Java: `getLockPwd()`) — **required** in the "22" BLE frame as `m86803d(hc)` (interleaved: `"0"+digit` per char). Without it the lock sends a silent NACK. |
| `hubid` | `"PGH220UG2082979T"` | Hub serial — required in `senddata` and `cachedstatus` requests |
| `iotdm` | `"M2T200438609"` | Aliyun IoT device model — `mdna` field in `senddata` |
| `iothost` | `"a1GuxeFynXG.iot-as-mqtt.us-west-1.aliyuncs.com"` | Aliyun IoT broker hostname (per-hub Aliyun credentials — do NOT connect HA directly, would disconnect the hub) |
| `iotsecret` | `"2c28eb11..."` | Aliyun IoT device secret — HMAC-SHA256 key for Aliyun auth |
| `iotprodkey` | `"a1GuxeFynXG"` | Aliyun IoT product key |
| `adminAcuId` | `1234567` | Admin ACU ID — required for guest management API calls |
| `lockType` | `"PGD628FN"` | Hardware model code — shown in HA device info |

---

## Adding a new entity

1. Add a new `*Entity` class in a new or existing `*.py` platform file.
2. Read state from `self.coordinator.data[self._lock_id]` — the merged dict of lock fields and live/cached status.
3. Register in `async_setup_entry` iterating `coordinator.locks`.
4. Add the platform name to `PLATFORMS` in `__init__.py`.

Do not store coordinator data in entity instance variables — always re-read from `self.coordinator.data` in properties so the entity reflects the latest coordinator state.

---

## Adding a new API call

1. Add the async function to `api.py`.
2. Encrypt the payload with `des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))`.
3. Use `{**COMMON_BODY, "para": para}` as the request body.
4. Pass `headers=_headers(jwt)` to include the Authorization header.
5. Check `str(body.get("cod")) != "200"` before reading response fields.
6. Never call `senddata`-based functions from `_async_update_data`.

---

## Access log event fields

Events returned by `getlkhist` are `HistoryUploadRequest.OpenLock` objects. The JSON keys are the **raw Java field names** — there are no `@SerializedName` annotations, so the keys are short:

| JSON key | Type | Meaning |
|---|---|---|
| `co` | string | Event type (lock, unlock, access denied, etc.) |
| `tm` | long | Timestamp in epoch ms |
| `na` | string | Operator name — may be empty for anonymous keypad/fingerprint entries |
| `id` | long | Lock record ID — use for deduplication |
| `pid` | int | Credential/keypad slot ID used |
| `logVer` | int | Log version |

Do not use `eventType`, `lockUserName`, `timestamp`, `eventId`, etc. — those are imagined getter names that do not exist in the serialised JSON.

---

## MQTT real-time push

The integration connects to the Lockly Paho MQTT broker at startup (`mqtt.py`):
- **Broker:** `mqttuswest02-lb-001-b5ed8c5e37b3a497.elb.us-west-2.amazonaws.com:8883` (TLS)
- **Auth:** username = account email, password = JWT bearer token
- **Topic:** `"server"` (single topic; filter by `header.name` in each message)
- **DEVICE_STATE payload:** `{"header": {"name": "deviceStateCallback"}, "items": [{"deviceId": "<lock_id_lowercase>", "states": [{"statusKey": "LOCKED_STATUS", "statusValue": "0|1"}, {"statusKey": "MAGNET", "statusValue": "0|1"}]}]}`

**Do NOT connect to Aliyun IoT** using the per-lock `iothost`/`iotdm`/`iotsecret` fields from BackupLockBean. Those are the hub's device-identity credentials on Aliyun. Connecting with the same clientId as the hub **will disconnect the hub**, breaking the BLE relay for lock commands.

MQTT is additive — if the broker rejects the connection (logged at WARNING), the coordinator continues in polling-only mode without errors.

---

## Error codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `909` | Server cannot parse request — usually means `para` field is missing or unencrypted |
| `900` | Hub-level system error — for `cachedstatus` this means hub firmware is too old |
| `901` | No lock found |
| `942` | MQTT timeout — hub did not receive a BLE response from the lock in time ("Poor Internet Connection"). Transient; safe to retry. |

---

## Known limitations

- **Silent polling requires hub firmware build ≥ 422** (major version 2). The tested hub (`PGH220UG2082979T`) runs `2.2.04.17` (build 417) which is 5 builds short.
- **State staleness on old hubs**: when `cachedstatus` is unsupported, lock state in HA only updates when commanded through HA or when the integration restarts (one-time startup query).
- **MQTT push requires live verification**: The Lockly Paho broker (`mqtt.py`) connects using JWT auth. The exact username format and topic payload field names were derived from APK analysis but have not been confirmed against a live broker session. If `rc=4` on connect, the username format may need adjustment.
- **RSA keys are app-version-specific**: embedded keys are from APK 3.2.9. A key rotation by Lockly breaks authentication.
- **Bluetooth-only locks**: not supported. Requires a PGH-series hub connected to the internet.
