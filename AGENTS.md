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
  jadx_out/         # Decompiled APK Java source (read-only reference)
  lockly_traffic.jsonl  # Captured live API traffic (read-only reference)
```

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

### 6. `_pending_live_init` must be discarded unconditionally

`_pending_live_init` tracks locks that still need a one-time startup BLE query. The discard **must happen before** calling `api_query_lock_status`, not inside the success branch:

```python
# CORRECT — always one-time, even if query fails
if status is None and lock_id in self._pending_live_init:
    self._pending_live_init.discard(lock_id)
    status = await api_query_lock_status(...)

# WRONG — failed queries stay in the set and are retried every poll
if status is None and lock_id in self._pending_live_init:
    status = await api_query_lock_status(...)
    if status is not None:
        self._pending_live_init.discard(lock_id)  # never reached on failure
```

On hubs where `cachedstatus` is unsupported (`_cache_supported = False`), every poll produces `status = None`. If a lock stays in `_pending_live_init` after a failed query, `api_query_lock_status` (senddata) is called again on every 30-second poll — making the lock beep constantly and leaving its `is_locked` field unpopulated (showing as unavailable in HA).

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
- **No push/MQTT**: The Lockly app receives real-time state updates via an MPPS push channel (device subscribes to a channel named by lock UUID). This is not implemented; implementing it would solve the staleness issue.
- **RSA keys are app-version-specific**: embedded keys are from APK 3.2.9. A key rotation by Lockly breaks authentication.
- **Bluetooth-only locks**: not supported. Requires a PGH-series hub connected to the internet.
