# Lockly Cloud API — Protocol Reference

This document describes the Lockly cloud API as reverse-engineered from the Lockly Android app (version 3.2.9, APK SHA-256 `e84c8a49d2...`). It is intended to help developers extend or improve the Home Assistant integration, or to build other Lockly tooling.

> **Legal notice.** This information was obtained by analysing a legally-obtained copy of the app for interoperability purposes. Nothing in this document enables bypassing any security control on a lock that is not yours.

---

## Table of Contents

1. [Protocol Overview](#1-protocol-overview)
2. [Transport](#2-transport)
3. [Authentication — Login](#3-authentication--login)
4. [RSA-1024 NoPadding Encryption](#4-rsa-1024-nopadding-encryption)
5. [Device Discovery — qrylknew](#5-device-discovery--qrylknew)
6. [DES3/ECB para Encryption](#6-des3ecb-para-encryption)
7. [BLE Frame Format](#7-ble-frame-format)
8. [AES-128/ECB BLE Payload Encryption](#8-aes-128ecb-ble-payload-encryption)
9. [QueryLockStatus Command](#9-querylockstatus-command)
10. [Lock Status ACK Parsing](#10-lock-status-ack-parsing)
11. [NewUnlock Command](#11-newunlock-command)
12. [NewLock Command](#12-newlock-command)
13. [Live Status — senddata Endpoint](#13-live-status--senddata-endpoint)
14. [Silent Status — lock/cachedstatus/get Endpoint](#14-silent-status--lockcachedstatusget-endpoint)
15. [Token Refresh](#15-token-refresh)
16. [Lock Data Fields Reference](#16-lock-data-fields-reference)
17. [Endpoint Quick Reference](#17-endpoint-quick-reference)
18. [CRC-8 Algorithm](#18-crc-8-algorithm)
19. [Reverse Engineering Notes](#19-reverse-engineering-notes)

---

## 1. Protocol Overview

The Lockly cloud API is a plain HTTPS JSON API. Every request carries a fixed set of "common body" fields plus endpoint-specific fields. Sensitive fields are encrypted at the application layer — the outer transport is already TLS, but Lockly adds a second layer of RSA or DES3 encryption on top.

```
Client                        Lockly Cloud API              Lockly Hub              Lock
  |                                  |                           |                    |
  |--POST login (RSA para)---------->|                           |                    |
  |<--JWT (Authorization header)-----|                           |                    |
  |                                  |                           |                    |
  |--POST qrylknew (RSA para)------->|                           |                    |
  |<--encrypted lock list (DES3)-----|                           |                    |
  |                                  |                           |                    |
  |--POST cachedstatus/get (DES3)--->|                           |                    |
  |<--cached sts bitmap--------------|                           |                    |
  |                                  |                           |                    |
  |--POST senddata (DES3 para)------>|--BLE frame (AES)--------->|--BLE packet------->|
  |<--ACK (BLE response frame)-------|<--------------------------|<-------------------|
```

### Common request body

Every API request (except `login`) carries these fields verbatim:

```json
{
  "appType": "LOCKLY",
  "ctry":    "",
  "dvid":    "",
  "locale":  "EN",
  "os":      "android",
  "rid1":    "",
  "rid2":    "",
  "tk":      "",
  "ver":     "329",
  "versionName": "3.2.9"
}
```

---

## 2. Transport

- **Base URL:** `https://apiserv03c.lockly.com/pgsmtlkv2/api/`
- **Method:** `POST` for all endpoints
- **Content-Type:** `application/json; charset=UTF-8`
- **User-Agent:** `DoorLocker/329 (Pixel 8 Pro; Android 16)`
- **Accept-Encoding:** `gzip`
- **Authorization:** `Bearer <jwt>` on all authenticated endpoints (see §3)

---

## 3. Authentication — Login

### Request

```
POST /pgsmtlkv2/api/login
```

The `para` field is an RSA-1024/NoPadding encrypted JSON string (see §4):

```json
{
  ...common_body...,
  "para": "<base64(RSA_encrypt({'acct': email, 'pw': sha256hex(password)}))>"
}
```

Password hashing (`SHA256Util.m87491b` in the APK):
```python
import hashlib
pw_hash = hashlib.sha256(password.encode()).hexdigest()  # lowercase hex
```

### Response

HTTP status 200, body:
```json
{"cod": "200"}
```

The JWT is **not in the body** — it is in the HTTP response header:
```
Authorization: Bearer eyJhbGci...
```

The `TokenRenewInterceptor` OkHttp interceptor extracts this header after every successful API call and stores it in `SharedPreferences`. Any API call can refresh the token.

Token lifetime is approximately 24 hours. When expired the server returns `cod != "200"` on any endpoint; handle by re-calling `login`.

---

## 4. RSA-1024 NoPadding Encryption

Lockly uses two independent RSA-1024 key pairs, both extracted from `libkey.so` in the APK.

### Key extraction method

The keys are stored as base64 fragments obfuscated across two byte-interleaved constants. They are reconstructed at runtime by `KeyManager.java`:

```python
import base64
from Crypto.PublicKey import RSA

with open("libkey.so", "rb") as f:
    libkey = f.read()

# Public key (for encrypting requests)
key1 = b"DJQ6E4BxAJQJU0A4Ao49GFNWA6DPCDBf"
key2 = b"UM1IyGyffMBA70DGgCJShqiGkSPI7b13"
output_A = bytes([key2[i] for i in range(1, 32, 2)])
output_B = bytes([key1[i] for i in range(0, 32, 2)])
pub_header = base64.b64decode(output_A) + base64.b64decode(output_B)
null_pos = libkey.index(b"\x00", 0x179DC)
pub_tail = base64.b64decode(libkey[0x179DC:null_pos].decode("ascii") + "==")
pub_key = RSA.import_key(pub_header + pub_tail)

# Private key (for decrypting server responses)
privkey1 = b"h1kFihGP92wx0FBlAkQpE+FyAyA+ShCs"
privkey2 = b"NMOI/IbCDdlQBIkBfAeDpAqNLBSgPkWq"
priv_A = bytes([privkey2[i] for i in range(1, 32, 2)])
priv_B = bytes([privkey1[i] for i in range(0, 32, 2)])
priv_raw = libkey[0x1661B:libkey.index(b"\x00", 0x1661B)]
priv_key = RSA.import_key(
    base64.b64decode(priv_A + b"==") + base64.b64decode(priv_B + b"==") +
    base64.b64decode(priv_raw + b"==")
)
```

### Encrypt (for `para` field in requests)

```python
def rsa_encrypt_para(json_str: str, pub_key) -> str:
    msg = json_str.encode("utf-8")
    key_size = (pub_key.n.bit_length() + 7) // 8  # 128 bytes for RSA-1024
    padded = b"\x00" * (key_size - len(msg)) + msg  # zero-pad on left
    c = pow(int.from_bytes(padded, "big"), pub_key.e, pub_key.n)
    return base64.b64encode(c.to_bytes(key_size, "big")).decode("ascii")
```

This is raw RSA (no PKCS#1 or OAEP padding). The plaintext must be shorter than the key modulus (128 bytes for RSA-1024). The login payload `{"acct":"...","pw":"<64-char-hex>"}` is typically ≈90 bytes, well within limits.

### Decrypt (for server `key` field in `qrylknew` response)

```python
def rsa_decrypt_key(key_b64: str, priv_key) -> str:
    ct = base64.b64decode(key_b64 + "==")
    m = pow(int.from_bytes(ct, "big"), priv_key.d, priv_key.n)
    pt = m.to_bytes((priv_key.n.bit_length() + 7) // 8, "big")
    return pt.lstrip(b"\x00").decode("ascii")  # 32-char ASCII string
```

### Embedded key DER bytes (app version 3.2.9)

The keys are pre-extracted and embedded in `api.py` as base64-DER constants:

```
Public key (request encryption):
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZtiijnvRo5EEI0n2I7shxljMX...

Private key (response decryption):
MIICWwIBAAKBgQDAWboNKfQkSLGSPqN6zI9XZSrewBOdkJeOHUoFb2k1Wd2Vgdr0...
```

If Lockly ships an app update that changes these keys, the integration will fail at the RSA step. Re-extract from the new `libkey.so` using the code above.

---

## 5. Device Discovery — qrylknew

### Request

```
POST /pgsmtlkv2/api/qrylknew
Authorization: Bearer <jwt>
```

Body:
```json
{
  ...common_body...,
  "para": "<base64(RSA_encrypt({'acct': email}))>"
}
```

### Response

```json
{
  "cod": "200",
  "key": "<base64(RSA_encrypted_server_key)>",
  "dl":  ["<base64(DES3_ECB_encrypted_BackupLockBean_json)>", ...]
}
```

### Decryption

1. **Derive DES3 key:**
   ```python
   server_key_str = rsa_decrypt_key(body["key"], priv_key)  # → 32-char ASCII
   des3_key = base64.b64decode(server_key_str)[:24]         # → 24-byte DES3 key
   ```

2. **Decrypt each lock entry:**
   ```python
   pt = DES3.new(des3_key, DES3.MODE_ECB).decrypt(base64.b64decode(dl_entry + "=="))
   # strip PKCS7 padding, then JSON parse
   lock = json.loads(pt.rstrip(b"\x00"))
   ```

The DES3 key is account-scoped and consistent across sessions for the same account. All subsequent `senddata` requests use the same key.

---

## 6. DES3/ECB para Encryption

For `senddata` and similar endpoints the `para` field is DES3/ECB-encrypted instead of RSA-encrypted:

```python
from Crypto.Cipher import DES3
import base64

def des3_encrypt(key: bytes, plaintext: str) -> str:
    data = plaintext.encode("utf-8")
    pad = 8 - (len(data) % 8)
    data += bytes([pad] * pad)                            # PKCS7 padding to 8-byte boundary
    return base64.b64encode(DES3.new(key, DES3.MODE_ECB).encrypt(data)).decode()

def des3_decrypt(key: bytes, b64: str) -> bytes:
    ct = base64.b64decode(b64 + "==")
    pt = DES3.new(key, DES3.MODE_ECB).decrypt(ct)
    pad = pt[-1]
    return pt[:-pad] if 1 <= pad <= 8 else pt
```

---

## 7. BLE Frame Format

BLE commands and responses are transmitted as hex strings inside the API `cmd` / `ACK` fields. Two frame formats exist:

### Command frame (outgoing, host → lock)

```
┌─────────────────┬──────────────┬───────────────────┬──────────┬────────┐
│  Magic (4 B)    │  Length (2B) │  AES Payload (N B)│ Type (1B)│ CRC(1B)│
│  A1 B2 C3 D4   │  LE uint16   │  16 or 32 bytes   │ see below│  CRC-8 │
└─────────────────┴──────────────┴───────────────────┴──────────┴────────┘
Total frame length = N + 8.  Length field = total frame length.
```

**Type byte** encodes zero-padding and encryption type:
```
type_byte = (zero_pad_byte_count << 4) | encrypt_type
```
- `encrypt_type = 5` for AES-128/ECB (used for all hub commands)
- `zero_pad_byte_count` = number of `\x00` bytes appended to reach AES block boundary

### Response frame (incoming, lock → host)

```
┌─────────────────┬──────────────┬─────────────────┬───────────────────┬────────┐
│  Magic (4 B)    │  Length (2B) │  CmdType (2 B)  │  AES Payload (32B)│ CRC(1B)│
│  A1 B2 C3 D4   │  LE uint16   │  e.g. 0A 1E     │  two AES blocks   │  CRC-8 │
└─────────────────┴──────────────┴─────────────────┴───────────────────┴────────┘
Total = 41 bytes.
```

Note: the response frame inserts a 2-byte `CmdType` field between `Length` and `AES Payload`. There is **no** Type byte before the CRC.

**AES payload extraction (per `QueryLockStatusCmd.java` line 760):**
```python
payload_hex = ack_hex[16:-2]   # skip 8-char magic + 4-char length + 4-char cmdtype, drop 2-char CRC
```

**CmdType values:**
- `0A1E` — QueryLockStatus response
- `0A22` — NewUnlock / NewLock response

---

## 8. AES-128/ECB BLE Payload Encryption

All BLE payloads are encrypted with AES-128/ECB. The 16-byte key is derived per-lock from the lock's master code (`mc`) and device UUID (`ID`).

### AES key derivation (`DataUtils.m86653h`)

```python
def derive_aes_key(master_code: str, uuid: str) -> bytes:
    # Expand each decimal digit of mc with a leading "0"
    # e.g. "24860092" → "0204080600000902"
    expanded_hex = "".join("0" + c for c in str(master_code))
    mc_bytes = bytes.fromhex(expanded_hex)      # 8 bytes
    uuid_bytes = bytes.fromhex(uuid)            # 12 bytes (uuid is 24 hex chars)

    key = bytearray(16)
    for i in range(len(str(master_code))):      # 8 iterations for 8-digit mc
        key[i] = uuid_bytes[i] ^ mc_bytes[i]
    for i in range(8, 12):
        key[i] = uuid_bytes[i] ^ mc_bytes[i - 8]
    for i in range(12, 16):
        key[i] = uuid_bytes[i - 12]
    return bytes(key)
```

**Example** (Lock 0):
- `mc = "24860092"` → `expanded_hex = "0204080600000902"`
- `uuid = "2d0023003030471333363838"` → uuid_bytes
- Derived key: `2f042b0630304e113132303e2d002300`

### Master code XOR encoding (`HexUtils.m86806g`)

The master code is also encoded before inclusion in BLE frames:

```python
def encrypt_master_code(master_code: str, uuid: str) -> str:
    mc_bytes = bytes([int(c) for c in str(master_code)])  # digits as byte values
    uuid_bytes = bytes.fromhex(uuid)
    enc = bytes([mc_bytes[i] ^ uuid_bytes[i % len(uuid_bytes)] for i in range(len(mc_bytes))])
    return enc.hex().upper()  # 16 hex chars for 8-digit mc
```

---

## 9. QueryLockStatus Command

**BLE command code:** `1E` (CMD_NEW_QUERY_LOCK_STATUS)

### Plaintext content before AES encryption

```
1E  <mc_len>  <enc_mc>  <time_hex>  01
```

| Field | Length | Description |
|---|---|---|
| `1E` | 1 byte | Command code |
| `mc_len` | 1 byte | Length of `enc_mc` in bytes (8 for 8-digit mc) |
| `enc_mc` | 8 bytes | XOR-encoded master code (§8) |
| `time_hex` | 6 bytes | Current time as `yyMMddHHmmss`, each pair hex-encoded |
| `01` | 1 byte | is_remote = 1 (hub/cloud path) |

**Total: 17 bytes.** Zero-pad to 32 bytes (2 AES blocks), then AES-128/ECB encrypt.

### Building the frame

```python
from Crypto.Cipher import AES
from datetime import datetime

def build_query_status_cmd(master_code: str, uuid: str) -> str:
    enc_mc   = encrypt_master_code(master_code, uuid)
    mc_len   = f"{len(enc_mc) // 2:02x}"
    aes_key  = derive_aes_key(master_code, uuid)
    now      = datetime.now()
    time_str = now.strftime("%y%m%d%H%M%S")
    time_hex = "".join(f"{int(time_str[i:i+2]):02x}" for i in range(0, 12, 2))

    raw     = "1E" + mc_len + enc_mc + time_hex + "01"
    padding = "00" * (16 - (len(raw) // 2) % 16) if (len(raw) // 2) % 16 else ""
    padded  = raw + padding

    enc_payload  = AES.new(aes_key, AES.MODE_ECB).encrypt(bytes.fromhex(padded))
    pad_count    = len(padding) // 2
    type_byte    = bytes.fromhex(f"0{pad_count:X}5" if pad_count < 16 else f"{pad_count:X}5")[0]
    return build_ble_frame(enc_payload, type_byte).hex().upper()
```

---

## 10. Lock Status ACK Parsing

The `ACK` field in the `senddata` response is the response BLE frame as a hex string.

### Step 1 — Extract AES payload

```python
h           = ack_hex.upper()
payload_hex = h[16:-2]       # skip header(8) + length(4) + cmdtype(4); strip CRC(2)
payload     = bytes.fromhex(payload_hex)   # 32 bytes = 2 AES blocks
```

### Step 2 — AES decrypt

```python
decrypted = AES.new(aes_key, AES.MODE_ECB).decrypt(payload)
d         = decrypted.rstrip(b"\x00").hex()
```

### Step 3 — Parse fields

All offsets are character positions in the hex string (2 chars = 1 byte):

| Hex chars | Bytes | Field | Description |
|---|---|---|---|
| `d[0:8]` | 0–3 | firmware_version | 4-byte firmware version |
| `d[8:10]` | 4 | status_byte | Lock/sensor status bitmap |
| `d[10:14]` | 5–6 | wakeup_voltage | LE uint16; `raw × 10 mV` = battery voltage |
| `d[14:18]` | 7–8 | start_voltage | LE uint16; voltage when lock was last activated |
| `d[18:30]` | 9–14 | time | `yyMMddHHmmss` as 6 packed bytes |
| `d[30:32]` | 15 | prog_status | Programming status |
| `d[32:36]` | 16–17 | auto_unlock_delay | LE uint16; auto-lock delay in seconds |
| `d[36:38]` | 18 | lock_type | Lock type code |
| `d[38:54]` | 19–26 | lock_settings | 8 bytes of feature flags |

**Status byte bits** (`d[8:10]`):

| Bit | Mask | Name | Meaning when set |
|---|---|---|---|
| 0 | `0x01` | wired_door_sensor | Wired door sensor connected |
| 1 | `0x02` | is_unlocked | Lock is **open** (unlocked) |
| 2 | `0x04` | door_sensor_open | Door sensor reports door open |
| 4 | `0x10` | battery_invalid | Voltage reading not valid |

```python
status_byte   = int(d[8:10], 16)
is_locked     = not bool((status_byte >> 1) & 1)
wakeup_v_mv   = (int(d[10:12], 16) + int(d[12:14], 16) * 256) * 10  # millivolts
wakeup_v      = wakeup_v_mv / 1000                                   # volts
```

**Battery voltage mapping (4×AA):**
- Fresh (6.0 V) → ~100%
- Low (4.5 V) → ~0%
- Formula: `pct = clamp((v - 4.5) / 1.5 * 100, 0, 100)`

---

## 11. NewUnlock Command

**BLE command code:** `22` (NewUnlock, AES path for hub)  
**senddata directive:** `"U"`

### Plaintext content

```
22  <mc_len>  <enc_mc>  02  <pwd_expanded>  <pwd_id>  <time_hex>  01
```

| Field | Description |
|---|---|
| `22` | Command code |
| `mc_len` | 1 byte |
| `enc_mc` | 8 bytes (XOR-encoded mc) |
| `02` | Unlock type: `02` = HOST (normal unlock) |
| `pwd_expanded` | Password bytes (empty `""` for no password) |
| `pwd_id` | 2-byte LE uint16 of `pwdId` — typically `0100` (pwdId=1) |
| `time_hex` | 6-byte current time (yyMMddHHmmss) |
| `01` | is_remote = 1 (hub) |

Zero-pad to next AES block boundary (32 bytes), then AES-128/ECB encrypt.

**Note on unlock type:**
- `02` = HOST (standard remote unlock)
- `03` = LONG_TERM / STAFF (used for guest/staff credentials)

---

## 12. NewLock Command

**BLE command code:** `22` (same frame as NewUnlock, per APK analysis)  
**senddata directive:** `"L"`

`NewLockCmd.java` calls `NewUnlockCmd.getDataForHub(bluetoothBean, password, "2")` where `"2"` is `MessageManage.f55124e` (the lock-type flag vs `"1"` for unlock). The BLE frame structure is identical to §11; the server/hub uses the `directive` field to determine the intended operation.

---

## 13. Live Status — senddata Endpoint

**Causes the lock to beep.** Use §14 for silent polling.

### Request

```
POST /pgsmtlkv2/api/senddata
Authorization: Bearer <jwt>
```

The `para` field is DES3/ECB-encrypted JSON (§6):

```json
{
  "acct":  "user@example.com",
  "hubid": "PGH220UG2059895T",
  "dv":    "2d0023003030471333363838",
  "cmd":   "<BLE_frame_hex>",
  "mdna":  "M2T200434555",
  "directive": "U"   // "U"=unlock, "L"=lock; omit for query
}
```

Full request body:
```json
{
  ...common_body...,
  "para": "<base64(DES3_ECB_encrypt(inner_json))>"
}
```

### Response

```json
{
  "cod": "200",
  "ACK": "<BLE_response_frame_hex>"
}
```

The `ACK` field is parsed as described in §10.

**Timeout:** Allow 25–30 seconds. The server holds the HTTP connection open until the hub relays the lock's BLE response.

---

## 14. Silent Status — lock/cachedstatus/get Endpoint

**Does NOT contact the physical lock.** No beep. Returns the last state the hub uploaded to the cloud.

### Hub firmware requirement

This endpoint is only supported on hubs with a sufficiently recent firmware build. The check is performed client-side by `BluetoothBean.isSupportHubCacheStatus()` in the APK, and enforced server-side (older hubs return `cod=900`).

| Hub major version | Minimum build | Example |
|---|---|---|
| 2 | 422 | `2.2.04.22` |
| 4 | 401 | `4.0.04.01` |
| 6 | 503 | `6.0.05.03` |

The version string format is `MAJOR.MINOR.FIX.BUILD`. The check concatenates `FIX` and `BUILD` as a string and parses as an integer — e.g. `"2.2.04.17"` → major=2, build string=`"0417"` → 417 < 422 → **not supported**.

If the hub returns `cod=900`, it means the firmware predates the cached-status feature. The request format is correct; the hub simply does not support the endpoint. Upgrading the hub firmware via the Lockly app will enable it.

### Request

```
POST /pgsmtlkv2/api/lock/cachedstatus/get
Authorization: Bearer <jwt>
```

The `para` field is **DES3/ECB-encrypted** (same as all other post-auth endpoints — see §6):

```json
{
  ...common_body...,
  "para": "<base64(DES3_ECB_encrypt({'acct': email, 'dv': lock_id, 'hubid': hub_id}))>"
}
```

Inner JSON (before encryption):
```json
{
  "acct":  "user@example.com",
  "dv":    "2d0023003030471333363838",
  "hubid": "PGH220UG2082979T"
}
```

Source: `PGNetManager.getCacheStatus()` — `postBody.setPara(DES3Utils.m56333c(hubCacheStatusRequest.getJsonString(), LockerConfig.m61408T()))`. The `HubCacheStatusRequest` class has `@SerializedName("acct")` and `@SerializedName("dv")` fields.

> **Common mistake:** Sending `acct` and `dv` directly in the outer body (not encrypted in `para`) causes `cod=909`. Sending a correctly encrypted `para` but on a hub with old firmware causes `cod=900`.

### Response

```json
{
  "cod":  "200",
  "data": {
    "addr": "2d0023003030471333363838",
    "sts":  0,
    "time": 1715123456789
  }
}
```

The `time` field is a Unix timestamp in milliseconds. A value of `0` means the hub has never uploaded state for this lock (hub newly paired or just rebooted).

### Status bits (`sts` integer)

Defined in `HubCacheStatusData.java`:

| Bit | Constant | Meaning when set |
|---|---|---|
| 0 (`0x01`) | `LOCK_STATUS_BIT` | **Unlocked** (bit=0 means locked) |
| 1 (`0x02`) | `HAS_WIRED_DS_BIT` | Wired door sensor present |
| 2 (`0x04`) | `WIRED_DS_STATUS_BIT` | Wired door sensor open |
| 3 (`0x08`) | `HAS_RF_DS_BIT` | RF/wireless door sensor present |
| 4 (`0x10`) | `HAS_RF_STATUS_BIT` | RF door sensor open |
| 6 (`0x40`) | `SECURE_LOCK_BIT` | Secure-lock mode active |
| 7 (`0x80`) | `LOW_BAT_BIT` | Low battery |

```python
is_locked        = not bool(sts & 0x01)   # 0=locked, 1=unlocked
low_battery      = bool(sts & 0x80)
door_sensor_open = bool(sts & 0x04) if (sts & 0x02) else None
```

---

## 15. Token Refresh

```
POST /pgsmtlkv2/api/refresh
Authorization: Bearer <old_jwt>
```

Body: `{...common_body...}` (no additional fields needed)

The new JWT is returned in the response `Authorization` header, identical to login. This endpoint is hit by `TokenRenewInterceptor` transparently for each API call in the official app, but a simpler strategy (re-call `login` when any endpoint returns a non-200 code) also works.

---

## 16. Lock Data Fields Reference

Fields in the `BackupLockBean` JSON returned by `qrylknew` (decrypted from `dl[]`):

| JSON key | Java field | Type | Description |
|---|---|---|---|
| `ID` | `id` | string | Device UUID (24 hex chars) |
| `na` | `lockName` | string | **User-set friendly name** (e.g. "Front Door") |
| `blename` | `bleName` | string | BLE advertisement name (e.g. "LOCKLYAA009868") |
| `mc` | `masterCode` | int | Master code for AES key derivation |
| `hubid` | `hubId` | string | Hub serial number (e.g. "PGH220UG2059895T") |
| `iotdm` | `iotDeviceModel` | string | Aliyun IoT device name (e.g. "M2T200434555") |
| `iotprodkey` | `iotProductKey` | string | Aliyun IoT product key |
| `status` | `status` | int | Last known lock status from cloud |
| `pcStatus` | `pcStatus` | int | Power/charge status |
| `dn` | `deviceName` | string | Alternative device name |
| `lockType` | `lockType` | string | Hardware model code |

The `mc` (master code) and `ID` (UUID) are the two inputs needed to derive the AES key for all BLE commands. Guard these values — together they allow anyone with hub access to control the lock.

---

## 17. Endpoint Quick Reference

| Endpoint | Auth | Encryption | Purpose |
|---|---|---|---|
| `login` | None | RSA (para) | Authenticate, get JWT |
| `refresh` | Bearer JWT | None | Refresh JWT |
| `qrylknew` | Bearer JWT | RSA (para) + DES3 (response) | Get lock list + DES3 key |
| `senddata` | Bearer JWT | DES3 (para) + AES (BLE) | Live lock query / lock / unlock |
| `lock/cachedstatus/get` | Bearer JWT | DES3 (para) | Silent cached status (hub firmware ≥ 422 required) |

---

## 18. CRC-8 Algorithm

Lockly uses a non-standard CRC-8 implemented in `CrcUtils.java`. Lookup table (only 16 entries — processes 4 bits at a time):

```python
CRC8_LUT = [0, 49, 98, 83, 196, 245, 166, 151, 185, 136, 219, 234, 125, 76, 31, 46]

def crc8_lockly(data: bytes) -> int:
    crc = 0
    for byte in data:
        s4  = ((crc << 4) & 0xFF) ^ CRC8_LUT[(crc >> 4) ^ (byte >> 4)]
        crc = ((s4 << 4) & 0xFF) ^ CRC8_LUT[(s4 >> 4) ^ (byte & 0x0F)]
    return crc & 0xFF
```

The CRC covers all bytes of the frame **including** the type byte, but **excluding** the CRC byte itself.

---

## 19. Reverse Engineering Notes

### Methodology

1. **APK extraction** — `apktool` for smali disassembly; `jadx` for Java source decompilation.
2. **Key targets** — `libkey.so` for RSA constants; `HexUtils.java`, `DataUtils.java` for crypto helpers; `QueryLockStatusCmd.java`, `NewUnlockCmd.java` for BLE framing; `PGNetManager.java` for endpoint list.
3. **Traffic capture** — `mitmproxy` with certificate pinning bypass (Frida) to capture live API calls and correlate with decompiled code.
4. **Validation** — Python scripts (`probe23.py`–`probe25.py`) in `lockly_apk_analysis/` reproduce each discovered step and verify against live hardware.

### Key Java classes

| Class | Package | Role |
|---|---|---|
| `KeyManager` | `com.pg.lockly.key` | RSA key reconstruction from libkey.so |
| `HexUtils` | `…utils` | BLE frame/field builders (`m86802c`, `m86811l`) |
| `DataUtils` | `…utils` | AES key derivation (`m86653h`), master code expand |
| `QueryLockStatusCmd` | `…ble.cmd` | Status BLE frame build + ACK parse |
| `NewUnlockCmd` | `…ble.cmd` | Unlock/lock BLE frame |
| `PGNetManager` | `…api.network` | Retrofit API interface (all endpoints) |
| `TokenRenewInterceptor` | `…api.network.interceptor` | JWT extraction from response headers |
| `HubCacheStatusData` | `…api.network.response` | `sts` bitmask decoder |
| `BackupLockBean` | `…data.bean` | Lock JSON structure |
| `SHA256Util` | `…utils` | Password hashing |

### Known unknowns

- The `asyncsend` endpoint (async alternative to `senddata`) exists but is not used by this integration. The request format appears identical; the response is a callback rather than a synchronous ACK.
- **MPPS push channel** — the Lockly app subscribes to a push channel per lock at `apiserv04c.lockly.com/mpps/v1/channel` (GET to list channels, POST to manage subscriptions). The channel names are the lock UUIDs (e.g. `2D0023003030471333363838`). When the lock state changes, a push notification is delivered to these channels. Implementing this push subscription in HA would provide real-time state updates without any polling or BLE commands. The Aliyun IoT MQTT path (`iotdm`, `iotprodkey`) appears to be an alternative push mechanism for older firmware.
- Some Lockly hardware generations use an older BLE command set (command `7` = `HostUnlockCmd`). The integration targets AES-capable locks (command `22` = `NewUnlockCmd`); older locks are untested.
- The `lock/cachedstatus/get` response `time` field is a Unix timestamp in milliseconds. Values of 0 indicate the hub has never uploaded state for this lock.
