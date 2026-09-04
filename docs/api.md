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
15. [Access Log — getlkhist Endpoint](#15-access-log--getlkhist-endpoint)
16. [Guest Management — acu/ Endpoints](#16-guest-management--acu-endpoints)
17. [MQTT Real-Time Push](#17-mqtt-real-time-push)
18. [Token Refresh](#18-token-refresh)
19. [Lock Data Fields Reference](#19-lock-data-fields-reference)
20. [Endpoint Quick Reference](#20-endpoint-quick-reference)
21. [Error Codes](#21-error-codes)
22. [CRC-8 Algorithm](#22-crc-8-algorithm)
23. [Reverse Engineering Notes](#23-reverse-engineering-notes)
24. [Credential List — QueryPwd147 (0x93)](#24-credential-list--querypwd147-0x93)
25. [Lock-side BLE Error Codes](#25-lock-side-ble-error-codes)

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
        key[i] = uuid_bytes[i % len(uuid_bytes)] ^ mc_bytes[i]
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

| Bit | Mask | Name | Meaning when set | Confidence |
|---|---|---|---|---|
| 0 | `0x01` | door_circuit_open | Door circuit is open — the door is ajar, **or** no sensor is fitted | verified |
| 1 | `0x02` | is_unlocked | Lock is **open** (unlocked) | verified |
| 2 | `0x04` | *unknown* | Previously documented here as the door state. Read `0` in all six samples captured so far — but none of those paired it with a sensor-equipped door known to be open, so its meaning is genuinely untested, not disproven | unverified |
| 4 | `0x10` | battery_invalid | Voltage reading not valid | inferred from source |

Bit 0 was verified by physically opening a sensor-equipped door and watching it
change; a closed door completes the circuit and reads `0`. Note the consequence:
this byte carries **no sensor-presence flag**. An unfitted sensor is an open
circuit, so it reads `1` exactly like an open door, and the two cannot be
distinguished from a single sample. Only a `0` is unambiguous — it proves a
sensor exists. `parse_ack()` therefore reports the circuit state alone, and
`LocklyCoordinator` infers presence by remembering which locks have ever
reported closed.

Do not re-derive bit 0 as "sensor connected". That reading, and its inverse,
were both implemented and both wrong; each matched every sample then available
because those samples all happened to have the sensor-equipped doors shut. The
hub's `cachedstatus` `sts` integer (§14) uses a *different* layout that does
have presence flags — do not carry its bit meanings over to this byte.

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

**BLE command code:** `22` (NewUnlock, AES path) — but see *Command variants* below  
**senddata directive:** `"unlock"`

### Field assembly

`NewUnlockCmd.getData` builds the plaintext by passing an ordered argument list
to `HexUtils.m86802c`, which concatenates them with two rules that matter:

- a **one-character** argument is left-padded to two (`"2"` → `"02"`)
- an **empty** argument is skipped entirely (`TextUtils.isEmpty`), so an absent
  field disappears rather than becoming `00`

```
22  <mc_len>  <enc_mc>  <unlock_type>  <pwd>  <pwd_id>  <action>  <str3>  <nonce>
```

| Field | Java source | Value |
|---|---|---|
| `22` | literal | Command code |
| `mc_len` | `encryptMasterCode.length()/2` as **decimal** | `08` |
| `enc_mc` | `getEncryptMasterCode()` | 8 bytes, mc XOR uuid |
| `unlock_type` | `getUnLockType()` | `02` = host/admin, `03` = long-term or staff |
| `pwd` | `HexUtils.m86803d(getLockPwd())` | the lock's `hc`, digit-expanded — `"980798"` → `090800070908` |
| `pwd_id` | `DataUtils.m86645J(getPwdId())` | **`00` for a host** — see below |
| `action` | `MessageManage` type flag | `01` = unlock, `02` = lock |
| `str3` | **hub flag** | `01` when relayed by a hub, `00` for direct BLE |
| `nonce` | `m86660o` | 8 bytes — see below |

Zero-pad to the next AES block boundary, then AES-128/ECB encrypt. The frame's
type byte carries the zero-padding length in its high nibble and `5` (AES-128/ECB)
in its low nibble.

### `pwd_id` — the credential slot

`getPwdId()` returns `"1"` when the bean's `pwdId` is unset, and that default is
misleading: `LockerManager`, building the bean from stored lock data, assigns it
explicitly for an admin —

```java
bluetoothBean.setHost(true);
if (!myLockerBean.isSubAdmin()) {
    bluetoothBean.setPwdId("0");
}
```

so a host command carries slot **0**, not 1. `NewUnlockCmd`'s `0x52` branch does
the same for hosts. Slot 0 is where the host credential actually lives, which
§24 shows directly.

> Sending the host password with slot `01` makes the lock look up a *different*
> credential, compare the two, and reject the command with BLE error `FF`
> ("wrong password") — behind a `cod=200` from the cloud. This was the second of
> the two bugs that kept unlock from working; the first was `str3` below. Both
> had to be correct simultaneously.

### `str3` — the hub flag

This field decides nothing about the lock, but getting it wrong makes the lock
reject the command. Three entry points set it:

| Method | `str3` | Used for |
|---|---|---|
| `getDataForHub` | `"1"` | hub-relayed commands |
| `getDataForBluetooth` | `"0"` | direct BLE from the phone |
| `getDataForNetwork` | `"0"` | direct network send |

`OpenCloseRepositoryImpl` picks `getDataForHub` whenever `isRemoteControl()` is
set, and `NewLockCmd` calls it unconditionally. **Every cloud `senddata` command
is hub-relayed, so `str3` is always `01`.**

> This was the long-standing bug in this integration: it sent `00`, and the lock
> silently NACKed every unlock. It is easy to miss because `cod=200` still comes
> back — the cloud accepted the request and the hub relayed it; only the lock
> refused. Always check the ACK frame, not just `cod`.

### The nonce

```java
m86660o = isSupportTimestamp() ? DataUtils.m86660o(timestamp)
                               : LockerConfig.m61192B(uuid)
```

On locks where `isSupportTimestamp()` is false, the field is a value the **lock
itself** issued: `QueryLockStatusCmd` stores `data[38:54]` of the decrypted
status payload into `SharedPreferences` under `ble_aes_random_numbers_1062`,
keyed by lock uuid, and the next command replays it.

So the sequence is: query status → keep bytes 19–26 of the plaintext → send them
back in the next lock/unlock frame. The lock rotates the value as it is used, so
refresh it with a status query immediately before commanding, or the command is
rejected as stale. When no status response has ever been seen the field is
omitted entirely.

### Command variants

Lockly hardware does not share one frame format. `NewUnlockCmd.getData` branches
on `BluetoothBean` predicates, all of which resolve from a **numeric lock type**:

| Predicate | Command | Difference |
|---|---|---|
| default | `22` | the layout above |
| `isSupport82Cmd()` | **`52`** | `getUserId()` replaces `pwd_id`; encryptType 11/12/13 |
| `isSupport500GroupPassword()` | `22` | extra `02` after the command code; `getCmdLenString()` for the slot |

`isSupportTimestamp()` is `(isHost() && isVision()) || (isSupport82Cmd() && !isPGI301())`.

`BluetoothBean.getLockType()` parses the bean's `lockType` field and **falls back
to 1** when absent. `qrylknew` does not return `lockType` — the lock reports it
itself, as byte 18 of the decrypted status payload (`data[36:38]`, read by
`QueryLockStatusCmd`). Query status first, then build commands for the type it
reports.

Lock type numbers relevant to reported hardware:

| Type | Model | Variant |
|---|---|---|
| 4 | PGD628F | `22` |
| 21 | PGD628FN | `22` |
| 124 | PGD728FG25 | `52` |
| 125 | PGD728FNG25 | `52` |
| 127 | PGD628FG25 | `52` |
| 129 | PGD728FN21 | 500-group |
| 121 | PGI301 | `52`, no timestamp |

See `custom_components/lockly/capabilities.py` for the full ported sets.

---

## 12. NewLock Command

**BLE command code:** `22` (same frame as NewUnlock, per APK analysis)  
**senddata directive:** `"lock"`

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
  "directive": "unlock"  // "unlock" or "lock"; omit entirely for a status query
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

## 15. Access Log — getlkhist Endpoint

Returns the access event history for a lock (physical unlocks, lock events, denied attempts) since a given timestamp cursor.

### Request

```
POST /pgsmtlkv2/api/getlkhist
Authorization: Bearer <jwt>
```

Body:
```json
{
  ...common_body...,
  "para": "<base64(DES3_ECB_encrypt({'acct': email, 'ID': lock_id, 'time': str(since_ms)}))>"
}
```

| Field | Description |
|---|---|
| `acct` | Account email |
| `ID` | Lock device UUID (24 hex chars) |
| `time` | Cursor: epoch ms of last fetched event as a string (pass `"0"` for all history) |

### Response

```json
{
  "cod": "200",
  "el": [ ... ],
  "LAST_EVENT_SYNC_TIME": 1715123456789
}
```

| Field | Description |
|---|---|
| `el` | Event list — array of `HistoryUploadRequest.OpenLock` objects |
| `LAST_EVENT_SYNC_TIME` | Cursor for next call — save and pass as `time` on the next request |

Save `LAST_EVENT_SYNC_TIME` and pass it as `time` on the next call to receive only new events.

### Event object fields (`el[]`)

Fields are the raw Java field names from `HistoryUploadRequest.OpenLock` — there are **no** `@SerializedName` annotations; the short names are the JSON keys.

| JSON key | Type | Meaning |
|---|---|---|
| `co` | string | Event type (e.g. `"UNLOCK"`, `"LOCK"`, `"ACCESS_DENIED"`) |
| `tm` | long | Timestamp in epoch ms |
| `na` | string | Operator name — empty for anonymous keypad/fingerprint entries |
| `id` | long | Lock record ID (use for deduplication) |
| `pid` | int | Credential slot / keypad ID used |
| `logVer` | int | Log version |

**Important:** Do not use `eventType`, `lockUserName`, `timestamp`, `eventId`, etc. — those names do not exist in the serialised JSON.

---

## 16. Guest Management — acu/ Endpoints

All three endpoints use DES3/ECB-encrypted `para` (§6) and require a valid JWT.

### List guests — acu/crdntl/list

```
POST /pgsmtlkv2/api/acu/crdntl/list
```

Inner para JSON:
```json
{"dv": "<lock_id>", "adminAcuId": <admin_acu_id>}
```

`adminAcuId` is the integer from the `adminAcuId` field in `BackupLockBean` (§19).

Response (cod=200):
```json
{"cod": "200", "acuMediumList": [ ... ]}
```

Each item contains: `userAcuId`, `name`, `startTime`, `endTime`, `acuStatus` (`"Y"` = active, `"S"` = suspended).

### Add guest — acu/save

```
POST /pgsmtlkv2/api/acu/save
```

Inner para JSON:
```json
{
  "dv": "<lock_id>",
  "name": "Guest Name",
  "type": "GUEST",
  "userAcuId": 0,
  "acuStatus": "Y",
  "timeType": "MORE_LIMIT",
  "isRetry": false,
  "multipleVerific": 0,
  "acuGuest": {
    "startTime": <epoch_ms>,
    "endTime":   <epoch_ms>,
    "weekData":  0,
    "pw":        "1234",
    "pid":       1,
    "pwStatus":  "Y",
    "subadm":    "false",
    "oacpriv":   "false"
  }
}
```

**Critical field name:** the user type key is `"type"` (from `@SerializedName(Constants.OMK_TYPE)` where `Constants.OMK_TYPE = "type"`). Using `"tp"` instead will silently fail (cod=200 but wrong behaviour).

Response contains `userAcuId` for the new guest — save it for deletion.

> **Known limitation:** Whether `acu/save` auto-activates the PIN on the physical lock hardware is unconfirmed. If the PIN does not work physically, call `acu/crdntl/pwList/active` (see stub comment in `api.py`) after saving.

### Delete guest — acu/delete

```
POST /pgsmtlkv2/api/acu/delete
```

Inner para JSON:
```json
{"dv": "<lock_id>", "userAcuId": <user_acu_id>, "adminAcuId": <admin_acu_id>}
```

Response: `{"cod": "200"}` on success.

---

## 17. MQTT Real-Time Push

The Lockly mobile app receives real-time lock state changes via a Paho MQTT connection to a Lockly-operated broker. The HA integration replicates this to get push updates without polling.

### Broker

```
ssl://mqttuswest02-lb-001-b5ed8c5e37b3a497.elb.us-west-2.amazonaws.com:8883
```

Extracted from `PgConfig.smali` in the APK. Standard MQTT over TLS; port 8883.

### Authentication

| MQTT field | Value |
|---|---|
| `client_id` | Any random UUID (generate fresh at startup) |
| `username` | Account email (lowercase) |
| `password` | JWT bearer token (without the `Bearer ` prefix) |

The app's `MqttConnectionOption.getUserName()` returns `{user_client_id}_{email}` when a server-assigned `user_client_id` is stored in SharedPreferences, or falls back to just the email. For HA, the email-only fallback is used.

### Topic

`"server"` is the default `Message.TOPIC` value in the APK. Message type is
identified by `header.name` in the JSON payload.

> **Verified 2026-08-24 — subscribing to `server` is refused.** With
> `username = email` and `password = <jwt>`, the broker **accepts the TCP/TLS
> connection and the MQTT CONNECT** (rc=0), then returns **SUBACK 0x80** for
> `server` — i.e. subscription not authorised. So the credentials are good
> enough to connect but not to subscribe on that topic. Either the username
> needs the `{user_client_id}_{email}` form, or the topic is per-user/per-device
> rather than the shared `server`.
>
> This is worth knowing because the failure is otherwise invisible: paho's
> `on_connect` reports success and no message ever arrives. Log the SUBACK
> return code (`on_subscribe`'s `granted_qos`) — a value of 128 means refused,
> not "subscribed at QoS 128".

### Roadblock: no viable push path found

Real-time push is **blocked**, not merely unimplemented. Every avenue located so
far is closed, and the notes below exist so nobody repeats the work.

| Attempt | Result |
|---|---|
| `username = email`, `password = <jwt>` | CONNECT accepted (rc=0), subscription refused (SUBACK `0x80`) |
| Add the app's client certificate (mTLS, see above) | No change — client identity was not the blocker |
| `getHeartbeatTime` for a server-assigned client id | The returned `clientId` is an echo of the `deviceId` in the request, so `{clientId}_{email}` carries no new information |
| The broker address `getHeartbeatTime` reports | A different host from `PgConfig`'s, and it refuses CONNECT outright (`rc=5`) |
| `POST v1/proto/handler` | Request/response only, so structurally incapable of push; also gated (below) |

> **Superseded.** The section below concluded that push is impossible because
> the broker refuses the subscription and FCM gates registration. That is
> **wrong on the central point**: we were subscribing to the wrong topic.
> `server` is publish-only. The broker delivers to `client/<client_id>`, and it
> was observed doing so with no subscription granted at all. The FCM chain
> traced below is real but governs the app's *phone notification* registration
> (Firebase, Xiaomi, AIPN), not the MQTT device channel. See
> "Topics, corrected" immediately after.

### Topics, corrected

| Topic | Direction | Notes |
|---|---|---|
| `server` | client → broker | Publish only. `Message.TOPIC`. The app never subscribes to it; `Connection.java` has `publish()` and `messageArrived()` and no `subscribe()`. A `SUBACK 0x80` here is correct and harmless. |
| `client/<client_id>` | broker → client | Replies and state callbacks. Verified: a published command was answered here with no SUBSCRIBE issued, so the broker holds a server-side subscription. |

Sending a command, from `LockCommandController.sendCommand(bluetoothBean, byte[] bleData, ...)`:

```json
{"header":  {"namespace": "com.lockly", "name": "lockCommandRequest",
             "requestId": "<uuid>", "timestamp": 1788496170204},
 "payload": {"deviceId": "<lock uuid>", "commandName": "forward",
             "commandContent": "<base64 of the same BLE frame senddata carries>"}}
```

`commandName` is `"forward"` (`LockCommandRequestData.COMMAND_NAME`): the server
forwards the frame rather than interpreting it. Replies arrive as
`lockCommandResponse`, or `exception` with a code:

| Code | Meaning |
|---|---|
| `3005` | `device is offline` — the hub is not connected to this channel |

Observed end to end against a real account: CONNECT accepted, PUBLISH acknowledged,
and an `exception`/`3005` reply received. So the transport works in both
directions; whether a *command* succeeds depends on the hub being online on the
channel. A PGH220 on build 417 is not.

This makes the MQTT channel a **second command transport** independent of
`senddata`, which is the likely reason some accounts get `cod=930` from
`senddata` while their app works normally.

---

The FCM trace below is retained because it is accurate about notification
registration, and because it documents how a correct finding got attached to the
wrong feature:

**How the `user_client_id` is obtained.** It was previously recorded here
as an open question. Tracing it through the *Lockly Home* tree
(`jadx_home_out`, which was not being searched) answers it:

1. `LoginRepositoryImpl` calls `LockerConfig.ob(account, clientId)` on a
   successful login. The client id is *passed into* the login call rather than
   returned by it, so it is chosen by the client, not assigned by the server.
   Supplying our own value was never the problem.
2. Immediately after, login fires
   `JobService.A("com.pingenie.pro.push.action.login.register.push.service")`.
3. That action runs `JobService.u()`, which reads `LockerConfig.j0()` — and
   `j0()` returns `SpUtils.o("fcm_token_1026", "")`, a **Firebase Cloud
   Messaging token**. With no token it takes the no-token branch and never
   registers.

So FCM registration is what enables the app's **notification** push: Firebase and
Xiaomi notifications to the handset, the same dependency already noted for the
MPPS channel in §22.

**What this does not explain is the MQTT device channel**, and concluding that it
did was a mistake worth recording. The reasoning was: the subscription is
refused, here is an unobtainable credential in the login flow, therefore the
subscription is gated on it. Each step looked sound and the conclusion was
wrong, because the premise was never checked — we were subscribing to `server`,
which no client subscribes to. One publish test produced a server reply on
`client/<client_id>` and undid the whole chain.

The lesson is the cheap experiment first. Tracing FCM through two decompiled
apps took far longer than the publish test that actually settled it, and the
trace was performed on a question that only appeared to be the blocker.

> **A caution learned the hard way.** paho's network loop reconnects on its own,
> so an `rc=5` refusal becomes a connect-refuse-retry loop several times a
> minute against Lockly's broker. Treat `rc=5` as permanent and stop the loop.
> Guessing at credentials means sending authenticated traffic at their
> infrastructure, and that has consequences.

### `v1/proto/handler` — request/response, not push

```
POST /v1/proto/handler
```

`ApiService` posts a `Payload<LockLogRequestData>` and receives an
`MqttHttpResponse`, carrying the same message envelope MQTT uses:

```json
{"header": {"name": "...", "namespace": "...", "requestId": "...", "timestamp": 0},
 "payload": {"deviceId": "...", "startTime": "...", "endTime": "...",
             "limit": 0, "offset": 0}}
```

Two things to be clear about:

- **It cannot deliver push.** It is a request/response endpoint. Device-state
  push goes through `DeviceStateController`, which subscribes via `PahoService`
  — the broker is the only push transport.
- **It is gated.** `isSupportQueryLockLogByMQTT()` requires
  `isSupportWiFiLowEnergy()`, an explicit model list that excludes `PGD628FN`.

It remains interesting for a different reason: `PGD728FG25` **is** on that list,
so this is a plausible transport for the hub-less WiFi-native locks that cannot
use `senddata` at all.

### Message format

```json
{
  "header": {
    "name": "deviceStateCallback"
  },
  "items": [
    {
      "deviceId": "2d0023003030471333363838",
      "states": [
        {"statusKey": "LOCKED_STATUS", "statusValue": "0"},
        {"statusKey": "MAGNET",        "statusValue": "0"}
      ]
    }
  ]
}
```

| `header.name` | Meaning |
|---|---|
| `deviceStateCallback` | Lock/door state changed |
| `lockCommandResponse` | Response to a lock/unlock command sent via MQTT |
| `lockEventLogQueryResponse` | Access log event delivered in real time |

**State keys:**

| `statusKey` | `statusValue` |
|---|---|
| `LOCKED_STATUS` | `"0"` = unlocked, `"1"` = locked |
| `MAGNET` | `"0"` = door closed, `"1"` = door open |

### Note on Aliyun IoT

Each lock's `BackupLockBean` contains `iothost`, `iotdm`, `iotsecret`, `iotprodkey` — these are the **hub's Aliyun IoT** device credentials. **Do not connect the HA integration to Aliyun IoT using these credentials.** Doing so would connect with the same device identity as the hub, disconnecting the hub from the Aliyun broker and breaking the BLE relay for lock commands.

---

## 18. Token Refresh

```
POST /pgsmtlkv2/api/refresh
Authorization: Bearer <old_jwt>
```

Body: `{...common_body...}` (no additional fields needed)

The new JWT is returned in the response `Authorization` header, identical to login. This endpoint is hit by `TokenRenewInterceptor` transparently for each API call in the official app, but a simpler strategy (re-call `login` when any endpoint returns a non-200 code) also works.

---

## 19. Lock Data Fields Reference

Fields in the `BackupLockBean` JSON returned by `qrylknew` (decrypted from `dl[]`):

| JSON key | Java field | Type | Description |
|---|---|---|---|
| `ID` | `id` | string | Device UUID (24 hex chars) |
| `na` | `lockName` | string | **User-set friendly name** (e.g. "Front Door") |
| `blename` | `bleName` | string | BLE advertisement name (e.g. "LOCKLYAA009868") |
| `mc` | `masterCode` | int | Master code for AES key derivation |
| `hc` | `lockPwd` (`getLockPwd()`) | string | Lock admin password — required in the "22" BLE frame; without it the lock sends a silent NACK |
| `hubid` | `hubId` | string | Hub serial number (e.g. "PGH220UG2059895T") |
| `iotdm` | `iotDeviceModel` | string | Aliyun IoT device name used as `mdna` in `senddata` (e.g. "M2T200434555") |
| `iotprodkey` | `iotProductKey` | string | Aliyun IoT product key — do not use for direct MQTT connection from HA |
| `iothost` | `iothost` | string | Aliyun IoT broker hostname — hub's device identity; do not connect HA using these credentials |
| `iotsecret` | `deviceSecret` | string | Aliyun IoT HMAC secret — hub credential only |
| `adminAcuId` | `adminAcuId` | int | Admin ACU ID — required for `acu/crdntl/list` and `acu/delete` |
| `status` | `status` | int | Last known lock status from cloud |
| `pcStatus` | `pcStatus` | int | Power/charge status |
| `dn` | `deviceName` | string | Alternative device name |
| `lockType` | `lockType` | string | Hardware model code |

The `mc` (master code) and `ID` (UUID) are the two inputs needed to derive the AES key for all BLE commands. Guard these values — together they allow anyone with hub access to control the lock.

---

## 20. Endpoint Quick Reference

| Endpoint | Auth | Encryption | Purpose |
|---|---|---|---|
| `login` | None | RSA (para) | Authenticate, get JWT |
| `refresh` | Bearer JWT | None | Refresh JWT |
| `qrylknew` | Bearer JWT | RSA (para) + DES3 (response) | Get lock list + DES3 key |
| `senddata` | Bearer JWT | DES3 (para) + AES (BLE) | Live lock query / lock / unlock |
| `lock/cachedstatus/get` | Bearer JWT | DES3 (para) | Silent cached status (hub firmware ≥ 422 required) |
| `getlkhist` | Bearer JWT | DES3 (para) | Access log events since cursor |
| `acu/crdntl/list` | Bearer JWT | DES3 (para) | List guest PIN credentials |
| `acu/save` | Bearer JWT | DES3 (para) | Create guest with time-limited PIN |
| `acu/delete` | Bearer JWT | DES3 (para) | Delete guest by userAcuId |

---

## 21. Error Codes

Response codes appear in the `cod` field of all API responses. The `200` success code is a string in some endpoints, an integer in others — always compare as `str(cod) == "200"`.

| Code | Meaning |
|---|---|
| `200` | Success |
| `900` | Hub-level system error — for `cachedstatus`, this means the hub firmware predates the feature |
| `901` | No lock found |
| `909` | Server cannot parse request — `para` field missing or not DES3-encrypted |
| `910` | `para` sent unencrypted |
| `920` | Endpoint rejected the request (seen on `lockly/syspara`) |
| `930` | Hub/Secure LINK not associated with the lock. Reported by every user in issues #1 and #2 and on the HA forum. Two known causes: (a) the lock is not bound to a hub in the Lockly app; (b) the lock has **no hub at all** — WiFi-native models such as `PGD728FG25` connect directly to WiFi, so `hubid` is empty by construction and `senddata`, a hub-relay endpoint, cannot serve them |
| `931` | Secure LINK already bound to another account |
| `932` | Secure LINK does not exist |
| `938` | Secure LINK ID coding format error |
| `942` | MQTT timeout — hub did not receive a BLE response from the lock in time. Transient; retry is safe. Source: `HubBleBuilder` fires this after the MQTT response timer expires with log "MQTT超时" |
| `943` | Hub is offline (app falls back to direct Bluetooth) |
| `990` | General system error / poor network |

---

## 22. CRC-8 Algorithm

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

## 23. Reverse Engineering Notes

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

### Resolved since the first draft

- **The unlock frame.** `str3` is `01` for hub-relayed commands, not `00`; see §11.
  The earlier draft of this document described the field as `is_remote` and the
  integration hardcoded `00`, which made every unlock fail with a lock-side NACK
  behind a `cod=200` response.
- **The nonce.** It is the lock's own value from `data[38:54]` of the status
  payload, cached by the app under `ble_aes_random_numbers_1062` per uuid, and
  replayed in the next command. Not a timestamp on `isSupportTimestamp()==false`
  hardware.
- **Multiple frame formats.** Selected by a numeric lock type the lock reports in
  its status payload (`data[36:38]`), defaulting to 1. See §11 *Command variants*.
- **The credential slot.** A host command carries `pwd_id` **0**, not the `"1"`
  that `getPwdId()` returns by default — `LockerManager` assigns `"0"` for an
  admin. Sending slot 1 with the host password is rejected as `FF`, "wrong
  password". See §11.
- **Where the host password lives.** Slot 0 of the lock's own credential list,
  readable over `0x93` (§24). The cloud's `hc` is a copy that can fall behind,
  though on the hardware tested here the two matched.
- **MQTT client certificates exist.** `MqttSSLSocketFactory` loads a CA, a
  client certificate and a client private key into a `KeyManagerFactory` over
  TLSv1.2, so the broker does expect mutual TLS. Worth knowing — but presenting
  them did **not** make the subscription work, so client identity was not the
  blocker. Push is a roadblock; §17 lists everything tried.
- **Lock-side error codes.** Tabulated in §25. A rejection is a short
  unencrypted frame with cmd-type `0C`; `cod=200` from the cloud says nothing
  about whether the lock acted.

### Known unknowns

- The `asyncsend` endpoint (async alternative to `senddata`) exists but is not used by this integration. The request format appears identical; the response is a callback rather than a synchronous ACK.
- **Guest PIN hardware activation** — whether `acu/save` auto-pushes the PIN to the lock hardware or whether a separate `acu/crdntl/pwList/active` call is required has not been confirmed by live testing.
- **MPPS REST channel** — `apiserv04c.lockly.com/mpps/v1/channel` manages which channels an FCM-registered device subscribes to. This path requires Firebase Cloud Messaging and is not usable in HA. The Lockly Paho MQTT broker (§17) is the correct path for HA real-time push.
- Some Lockly hardware generations use an older BLE command set (command `7` = `HostUnlockCmd`). The integration targets AES-capable locks (command `22` = `NewUnlockCmd`); older locks are untested.
- The `lock/cachedstatus/get` response `time` field is a Unix timestamp in milliseconds. Values of 0 indicate the hub has never uploaded state for this lock.

---

## 24. Credential List — QueryPwd147 (0x93)

Reads the credentials a lock actually holds. This matters because the cloud's
`hc` field is only a *copy* of the host password — the app updates its own copy
locally after a successful `SetHostPwdCmd` (`BindLockManager`), so `hc` can fall
behind the lock. `QueryPwdUtil` asks the lock instead, and takes the entry whose
`pwd_id` is 0 as the lock password.

### Which query a lock uses

`QueryPwdUtil` branches three ways, in this order:

| Predicate | Path | Command |
|---|---|---|
| `isSupport100Passwords()` | PGI302W only | — |
| `isSupport500GroupPassword()` | PGD728FN21, PGD238T | `QueryPwd167Cmd` |
| `isSupport32GroupPassword()` | PGD628FN ≥ 4.03.01, others | **`QueryPwd147Cmd` (`0x93`)** |

### Request

```
93  <mc_len>  <enc_mc>  <page>  <nonce>
```

Assembled by the same `HexUtils.m86802c` rules as §11, so a one-character field
is left-padded and `page` is **hex** (page 10 is `0a`). Always uses the stored
nonce — `QueryPwd147Cmd` does not take the `isSupportTimestamp()` branch.

On a lock that is not shared by tenant access, `getTenantAccessAESKey`,
`getTenantAccessEncryptMasterCode` and `getTenantAccessEncryptType` all fall
back to the ordinary host derivations, so this reuses the same AES key and
`enc_mc` as every other command.

### Response

Sent over `senddata` with no `directive`, and paginated. Decrypted layout:

| Hex chars | Field |
|---|---|
| `0:2` | status — `00` is success |
| `2:4` | total pages |
| `4:6` | current page |
| `6:8` | total credentials |
| `8:10` | credentials in this page |
| `10:` | entries |

Repeat until `current page >= total pages`. Each entry:

```
user_type(1B)  pwd_size(1B)  password(pwd_size B)  pwd_id(1B)
```

followed by a 20-character schedule block on every entry **except** `pwd_id 0` —
the host credential carries no schedule. On 500-group locks `pwd_id` is 2 bytes
rather than 1.

Passwords are digit-expanded as in §11, so decoding is `Cmd.getEvenString` in
reverse — keep every second character (`090800070908` → `980798`).

> **Bound the entry loop by the page's credential count.** The decrypted block is
> zero-padded to the AES boundary, and 10 or more bytes of padding will otherwise
> parse as a phantom `pwd_id 0` entry with an empty password.

`QueryPwdCmd.NO_PASSWOED` (`a1b2c3d40a000c11019a`) is the sentinel for a lock
holding none — a valid empty answer, not a failure.

---

## 25. Lock-side BLE Error Codes

When the lock rejects a command it replies with a short, **unencrypted** frame
whose cmd-type byte is `0C` rather than `0A`, followed by a single error byte.
`Cmd.getErrorCode` reads that byte; `Cmd.getErrorInfo` maps it to a message.

```
A1B2C3D4 0A00 0C22 FF 98
         len  type err crc
```

| Code | Meaning |
|---|---|
| `F0` | Too many 4-digit access codes (max 10; use 5–8 digits) |
| `F1` | Battery too low for an OTA update |
| `F5` | Bluetooth connection problem |
| `F8` | Cannot change the password |
| `F9` | This credential's valid period has not started yet |
| `FA` | Lock reported a system error |
| `FB` | A maximum has been reached |
| `FD` | This door code has been used before |
| `FE` | System error (present in Lockly Home 1.4.8; unhandled in 3.2.9) |
| `FF` | **Wrong password** — the lock rejected the credential in the command |

A success carries an AES-encrypted status block instead, and its first byte is
`00` (`MessageManage.f55131l`).

> **`cod=200` does not mean the lock acted.** It means the cloud accepted the
> request and the hub relayed it. Always parse the ACK: a rejection is a short
> frame, a success is a full AES block. Reporting `cod=200` as success is how a
> silently-failing unlock can look like a working one.
