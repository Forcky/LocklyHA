"""Lockly API — all crypto + HTTP for the Lockly cloud API."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime
from typing import Any

import aiohttp
from Crypto.Cipher import AES, DES3
from Crypto.PublicKey import RSA

from .capabilities import (
    _NO_PASSWORDS_ACK,
    _STR3_DIRECT,
    _STR3_HUB,
    ACTION_LOCK,
    ACTION_UNLOCK,
    CMD_QUERY_PASSWORDS,
    CMD_QUERY_STATUS,
    DEFAULT_CAPABILITIES,
    LOG_RECORD_CHARS_WIDE,
    PAGING_DATE_UNLIMITED,
    PAGING_LOG_RECORD_CHARS,
    PAGING_TIME_UNLIMITED,
    UNLOCK_TYPE_HOST,
    LockCapabilities,
)
from .const import API_BASE, API_USER_AGENT, COMMON_BODY, SENDDATA_TIMEOUT

_LOGGER = logging.getLogger(__name__)


# ── Embedded RSA keys (extracted from libkey.so in Lockly APK 3.2.9) ─────────
# RSA-1024, NoPadding. Keys are DER-encoded, base64-stored.
# Re-extract if Lockly updates their APK's RSA keys.

_PUB_KEY_DER_B64 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZtiijnvRo5EEI0n2I7shxljMX"
    "b7mZ/FpjuS98MHGWuYYUrsiJQVgfPn29lmI/MDkhVc7oVTsg5BIyC0TUpZKTgxyF"
    "DZw08AdWKe9JZvzyGB00AGkRxcem2J64xJJ04o9FW6PDLF0gSvblZAvUdHU1YyfB"
    "7DgJhikP7lPrFNdGwwIDAQAB"
)
_PRIV_KEY_DER_B64 = (
    "MIICWwIBAAKBgQDAWboNKfQkSLGSPqN6zI9XZSrewBOdkJeOHUoFb2k1Wd2Vgdr0"
    "abwPNHBf0EF1Wzg4GlN8Q9GU5HhmOhD95UGsS8Bm0Atca3y5eK1STwbdqpNBLUk"
    "Le9vazmAczCUqdK+XzzJlQz6IKd53jJRYT9sRZZKfssvobG5L15rE/ZKWYwIDAQAB"
    "AoGAMtHCASZbdZarK6tW/+O532pAOFfhFtkT4Z1FaEg2ML1MeOq1Eaw53n6JThc0"
    "pC/0m4YBFqzIW6E9WizvPlVq0whdwS9gTytPhtEBmIfJeeqpNHcqCYgM+kLrODkp"
    "cqTTtNVSGRoTX2smJT41Za2bQ0U2RdZD251I3FMBCrKx13ECQQDmW4+M6KZmE3we"
    "8RbG8j/yu5zDkRIwDS4pYntRZJfEWfMUkcHc+rO69VcdyblGW8MsjTBtuzTvrWYH"
    "bxdLt6bJAkEA1cMWFMrhfoiB/SGtqkNXNQJeXyAQVGPKOwU+Lb4i6UBIy9pWXiQb"
    "5UUcwsomWSEkfil6vCHePjilaYsehaAtywJAfc9J4mp53swLgRapGvTZiid/IaxMo6"
    "O/L2kS8sweu2VpBjXpDFh76sLt1l4C63NYcC+YYIXbDn/EdpDsxzTBSQJAO8YfqJ"
    "TK1W0qnDQMse2+tw4Aga0fo9l7tWFT78qZTIwzTv2w5QZH3qai0j1g18+Susyyi2"
    "UVFmUUrBzA3jDaXQJAdQgL6YM1bfzmGxr1AwyvVRWyraazdIchcbml/6WGkC/Ic+"
    "5fsJErwHepUIDZVuai32KINOl1HsazhUbzIyITJg=="
)

_PUB_KEY_OBJ = None
_PRIV_KEY_OBJ = None


def _get_pub_key():
    global _PUB_KEY_OBJ
    if _PUB_KEY_OBJ is None:
        der = base64.b64decode(_PUB_KEY_DER_B64)
        _PUB_KEY_OBJ = RSA.import_key(der)
    return _PUB_KEY_OBJ


def _get_priv_key():
    global _PRIV_KEY_OBJ
    if _PRIV_KEY_OBJ is None:
        der = base64.b64decode(_PRIV_KEY_DER_B64)
        _PRIV_KEY_OBJ = RSA.import_key(der)
    return _PRIV_KEY_OBJ


# ── RSA NoPadding crypto ───────────────────────────────────────────────────────

def rsa_encrypt_para(json_str: str) -> str:
    """RSA-1024 NoPadding encrypt for API para field."""
    pub = _get_pub_key()
    msg = json_str.encode("utf-8")
    key_size = (pub.n.bit_length() + 7) // 8
    padded = b"\x00" * (key_size - len(msg)) + msg
    c = pow(int.from_bytes(padded, "big"), pub.e, pub.n)
    return base64.b64encode(c.to_bytes(key_size, "big")).decode("ascii")


def rsa_decrypt_key(key_b64: str) -> str:
    """RSA-1024 NoPadding decrypt server key field → 32-char ASCII string."""
    priv = _get_priv_key()
    ct = base64.b64decode(key_b64 + "==")
    m = pow(int.from_bytes(ct, "big"), priv.d, priv.n)
    pt = m.to_bytes((priv.n.bit_length() + 7) // 8, "big")
    return pt.lstrip(b"\x00").decode("ascii")


# ── DES3 crypto ───────────────────────────────────────────────────────────────

def des3_key_from_server_key(server_key_str: str) -> bytes:
    """base64-decode the 32-char server key → 24-byte DES3 key."""
    return base64.b64decode(server_key_str)[:24]


def des3_encrypt(des3_key: bytes, plaintext: str) -> str:
    """DES3/ECB encrypt with PKCS7 padding → base64 output."""
    data = plaintext.encode("utf-8")
    pad_len = 8 - (len(data) % 8)
    data += bytes([pad_len] * pad_len)
    return base64.b64encode(DES3.new(des3_key, DES3.MODE_ECB).encrypt(data)).decode("ascii")


def des3_decrypt(des3_key: bytes, b64_data: str) -> bytes:
    """DES3/ECB decrypt base64 ciphertext → bytes (PKCS7 stripped)."""
    ct = base64.b64decode(b64_data + "==")
    pt = DES3.new(des3_key, DES3.MODE_ECB).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 8 and all(b == pad for b in pt[-pad:]):
        pt = pt[:-pad]
    return pt


# ── BLE crypto helpers ────────────────────────────────────────────────────────

def derive_aes_key(master_code: str, uuid: str) -> bytes:
    """DataUtils.m86653h: 16-byte AES key from masterCode + device UUID."""
    expanded_hex = "".join("0" + c for c in str(master_code))
    mc_bytes = bytes.fromhex(expanded_hex)
    uuid_bytes = bytes.fromhex(uuid)
    result = bytearray(16)
    mc_len = len(str(master_code))
    for i in range(mc_len):
        result[i] = uuid_bytes[i % len(uuid_bytes)] ^ mc_bytes[i]
    for i in range(8, 12):
        result[i] = uuid_bytes[i] ^ mc_bytes[i - 8]
    for i in range(12, 16):
        result[i] = uuid_bytes[i - 12]
    return bytes(result)


def encrypt_master_code(master_code: str, uuid: str) -> str:
    """HexUtils.m86806g: XOR digit-bytes of masterCode with UUID bytes → hex."""
    mc_bytes = bytes([int(c) for c in str(master_code)])
    uuid_bytes = bytes.fromhex(uuid)
    return bytes([mc_bytes[i] ^ uuid_bytes[i % len(uuid_bytes)] for i in range(len(mc_bytes))]).hex().upper()


_CRC8_LUT = [0, 49, 98, 83, 196, 245, 166, 151, 185, 136, 219, 234, 125, 76, 31, 46]


def crc8_lockly(data: bytes) -> int:
    crc = 0
    for byte in data:
        s4 = ((crc << 4) & 0xFF) ^ _CRC8_LUT[(crc >> 4) ^ (byte >> 4)]
        crc = ((s4 << 4) & 0xFF) ^ _CRC8_LUT[(s4 >> 4) ^ (byte & 0x0F)]
    return crc & 0xFF


def build_ble_frame(payload: bytes, type_byte: int) -> bytes:
    HEAD = bytes([0xA1, 0xB2, 0xC3, 0xD4])
    total_len = len(payload) + 8
    frame_no_crc = HEAD + bytes([total_len % 256, total_len // 256]) + payload + bytes([type_byte])
    return frame_no_crc + bytes([crc8_lockly(frame_no_crc)])


def _assemble_fields(*fields: str) -> str:
    """Port of HexUtils.m86802c field concatenation.

    Each non-empty field is appended verbatim, except single-character fields,
    which are left-padded to two ("2" -> "02").  Empty fields are skipped
    entirely (TextUtils.isEmpty in the app) — that is how an absent nonce drops
    out of the frame rather than becoming "00".
    """
    out: list[str] = []
    for field in fields:
        if not field:
            continue
        out.append("0" + field if len(field) == 1 else field)
    return "".join(out)


def _aes_wrap(raw_hex: str, aes_key: bytes) -> str:
    """Zero-pad to a 16-byte boundary, AES-ECB encrypt, wrap in a BLE frame.

    The frame's type byte holds the zero-padding length in its high nibble
    (AESBean.getZeroPadding) and 5 = AES-128/ECB in its low nibble.
    """
    remainder = (len(raw_hex) // 2) % 16
    padding = "" if remainder == 0 else "00" * (16 - remainder)
    encrypted = AES.new(aes_key, AES.MODE_ECB).encrypt(bytes.fromhex(raw_hex + padding))
    type_byte = ((len(padding) // 2) << 4) | 0x5
    return build_ble_frame(encrypted, type_byte).hex().upper()


def _expand_digits(value: str) -> str:
    """HexUtils.m86803d: prepend "0" to each character ("980798" -> "090800070908")."""
    return "".join("0" + c for c in str(value)) if value else ""


def _timestamp_hex() -> str:
    """DataUtils.m86660o: current local time as packed yyMMddHHmmss (6 bytes)."""
    time_str = datetime.now().strftime("%y%m%d%H%M%S")
    return "".join(f"{int(time_str[i:i+2]):02x}" for i in range(0, 12, 2))


def build_query_status_cmd(master_code: str, uuid: str) -> str:
    """Build QueryLockStatus BLE command hex string for senddata 'cmd' field."""
    enc_mc = encrypt_master_code(master_code, uuid)
    raw = _assemble_fields(
        CMD_QUERY_STATUS,
        f"{len(enc_mc) // 2:d}",
        enc_mc,
        _timestamp_hex(),
        _STR3_HUB,
    )
    return _aes_wrap(raw, derive_aes_key(master_code, uuid))


def _build_cmd_hex(
    cmd_code: str,
    master_code: str,
    uuid: str,
    lock_pwd: str = "",
    *,
    action: str = ACTION_UNLOCK,
    nonce: str | None = None,
    via_hub: bool = True,
    slot_id: int = 1,
    unlock_type: str = UNLOCK_TYPE_HOST,
) -> str:
    """Build an AES-encrypted lock/unlock BLE command frame.

    Field order is NewUnlockCmd.getData -> HexUtils.m86802c:

        cmd + mc_len + enc_mc + unlock_type + pwd + slot_id + action + str3 + nonce

    - ``lock_pwd`` is the lock's "hc" field (BluetoothBean.getLockPwd()), digit
      expanded by HexUtils.m86803d.  The lock NACKs a command that omits it.
    - ``via_hub`` selects str3: getDataForHub passes "1", getDataForBluetooth and
      getDataForNetwork pass "0".  Every cloud senddata command is relayed by a
      hub, so this is "01" — sending "00" here is what made unlock fail before.
    - ``nonce`` is the 8-byte value from the lock's last status ACK
      (QueryLockStatusCmd stores data[38:54] as ble_aes_random_numbers_1062).
      When None the field is omitted, matching the app before it has ever seen a
      status response.
    - ``slot_id`` is DataUtils.m86645J(pwdId), or getUserId() on 0x52 locks.
    """
    enc_mc = encrypt_master_code(master_code, uuid)
    raw = _assemble_fields(
        cmd_code,
        f"{len(enc_mc) // 2:d}",
        enc_mc,
        unlock_type,
        _expand_digits(lock_pwd),
        f"{slot_id:x}",
        action,
        _STR3_HUB if via_hub else _STR3_DIRECT,
        (nonce or "").upper(),
    )
    return _aes_wrap(raw, derive_aes_key(master_code, uuid))


def build_unlock_cmd(
    master_code: str,
    uuid: str,
    lock_pwd: str = "",
    nonce: str | None = None,
    *,
    caps: LockCapabilities | None = None,
) -> str:
    """Build a NewUnlock BLE command frame for a hub-relayed unlock.

    lock_pwd must be the "hc" field from BackupLockBean (getLockPwd()); omitting
    it causes a silent NACK from the lock.
    """
    return _build_cmd_hex(
        (caps or DEFAULT_CAPABILITIES).cmd_code,
        master_code,
        uuid,
        lock_pwd,
        action=ACTION_UNLOCK,
        nonce=nonce,
        slot_id=(caps or DEFAULT_CAPABILITIES).slot_id,
    )


def build_lock_cmd(
    master_code: str,
    uuid: str,
    lock_pwd: str = "",
    nonce: str | None = None,
    *,
    caps: LockCapabilities | None = None,
) -> str:
    """Build a NewLock BLE command frame.

    NewLockCmd reuses NewUnlockCmd's builder (NewLockCmd.execute calls
    newUnlockCmd.getDataForHub); only the action field and the API directive
    differ from unlock.
    """
    return _build_cmd_hex(
        (caps or DEFAULT_CAPABILITIES).cmd_code,
        master_code,
        uuid,
        lock_pwd,
        action=ACTION_LOCK,
        nonce=nonce,
        slot_id=(caps or DEFAULT_CAPABILITIES).slot_id,
    )


def build_query_pwd_cmd(
    master_code: str,
    uuid: str,
    position: int = 0,
    nonce: str | None = None,
) -> str:
    """Build a QueryPwd147 (0x93) frame — reads the lock's credential list.

    QueryPwd147Cmd.getData assembles: cmd + mc_len + enc_mc + position + nonce.
    It always uses the stored nonce, not the timestamp branch.

    On a lock that is not shared via tenant access, getTenantAccessAESKey /
    getTenantAccessEncryptMasterCode / getTenantAccessEncryptType all fall back
    to the ordinary host derivations, so this reuses the same key and enc_mc as
    every other command.

    The response is paginated; ``position`` is the page index.
    """
    enc_mc = encrypt_master_code(master_code, uuid)
    raw = _assemble_fields(
        CMD_QUERY_PASSWORDS,
        f"{len(enc_mc) // 2:d}",
        enc_mc,
        f"{position:x}",
        (nonce or "").upper(),
    )
    return _aes_wrap(raw, derive_aes_key(master_code, uuid))


def _decode_pwd_digits(hex_str: str) -> str:
    """Reverse HexUtils.m86803d — Cmd.getEvenString keeps every second character.

    "090800070908" -> "980798"
    """
    return hex_str[1::2]


def parse_pwd_list_ack(
    ack_hex: str,
    master_code: str,
    uuid: str,
    five_hundred_group: bool = False,
) -> dict[str, Any] | None:
    """Parse a QueryPwd147 (0x93) response into credential entries.

    Decrypted layout (QueryPwd147Cmd.parseCmd):

        [0:2]  status — "00" is success
        [2:4]  total pages
        [4:6]  current page
        [6:8]  total credentials
        [8:10] credentials in this page
        [10:]  entries, parsed by QueryPwdCmd.parseData

    Each entry (QueryPwdCmd.parseData):

        user_type(1B) | pwd_size(1B) | password(pwd_size B) | pwd_id(1B)

    followed by a 20-character schedule block, except when pwd_id is 0 — the
    host credential carries no schedule.  ``pwd_id == 0`` is the host password:
    QueryPwdUtil picks exactly that entry as the lock password.
    """
    h = ack_hex.upper()
    if h.lower() == _NO_PASSWORDS_ACK:
        return {"status_ok": True, "entries": [], "is_end": True, "total": 0}
    try:
        payload = bytes.fromhex(h[16:-2])
        if len(payload) == 0 or len(payload) % 16 != 0:
            code = h[16:18]
            _LOGGER.debug(
                "query passwords rejected: %s — %s", code, describe_ble_error(code)
            )
            return None
        d = AES.new(derive_aes_key(master_code, uuid), AES.MODE_ECB).decrypt(payload).hex()
        if len(d) < 10 or d[0:2] != "00":
            _LOGGER.debug("query passwords: status %s", d[0:2] if d else "(empty)")
            return None

        total_pages = int(d[2:4], 16)
        cur_page = int(d[4:6], 16)
        result: dict[str, Any] = {
            "status_ok": True,
            "total_pages": total_pages,
            "cur_page": cur_page,
            "total": int(d[6:8], 16),
            "page_count": int(d[8:10], 16),
            "is_end": cur_page >= total_pages,
            "entries": [],
        }

        rest = d[10:]
        # parseData loops while at least 20 characters remain, but the block is
        # zero-padded to the AES boundary and 10+ bytes of padding would parse as
        # a bogus slot-0 entry.  The page's own credential count bounds it.
        page_count = result["page_count"]
        while len(rest) >= 20 and len(result["entries"]) < page_count:
            user_type = int(rest[0:2], 16)
            pwd_size = int(rest[2:4], 16)
            pwd_end = 4 + pwd_size * 2
            password = _decode_pwd_digits(rest[4:pwd_end])
            if five_hundred_group:
                id_end = pwd_end + 4
                pwd_id = int(rest[pwd_end:id_end], 16)
            else:
                id_end = pwd_end + 2
                pwd_id = int(rest[pwd_end:id_end], 16)
            result["entries"].append(
                {"user_type": user_type, "pwd_id": pwd_id, "password": password}
            )
            # QueryPwdCmd.parseData skips the 10-byte schedule block when the
            # credential is the host (pwd_id 0) or user_type is 2.  Getting this
            # wrong consumes bytes belonging to the next entry and misaligns
            # every credential after it.
            has_schedule = pwd_id != 0 and user_type != 2
            rest = rest[id_end + 20:] if has_schedule else rest[id_end:]
        return result
    except Exception:
        _LOGGER.exception("Failed to parse password list ACK: %s", ack_hex[:60])
        return None


def parse_ack(ack_hex: str, master_code: str, uuid: str) -> dict[str, Any]:
    """Parse ACK field from senddata response.

    Response BLE frame: HEAD(4)+LEN(2)+CMD_TYPE(2)+AES_PAYLOAD(32)+CRC(1) = 41 bytes
    AES payload = ack_hex[16:-2]
    """
    h = ack_hex.upper()
    payload_hex = h[16:-2]
    aes_key = derive_aes_key(master_code, uuid)

    try:
        payload = bytes.fromhex(payload_hex)
        if len(payload) % 16 != 0:
            # Short/misaligned payload means the lock sent an error/nack frame.
            _LOGGER.debug("ACK payload not AES-aligned (%d bytes) — lock returned error/nack", len(payload))
            return {}
        # Keep the full decrypted hex: trailing 0x00 bytes are meaningful padding
        # for the fixed field offsets below, and stripping them truncates the
        # lock type and nonce fields near the end of the block.
        d = AES.new(aes_key, AES.MODE_ECB).decrypt(payload).hex()

        if len(d) < 10:
            _LOGGER.warning("Decrypted ACK too short: %s", d)
            return {}

        status_byte = int(d[8:10], 16)
        result: dict[str, Any] = {
            "firmware_version": d[0:8],
            "is_locked": not bool((status_byte >> 1) & 1),
            "door_sensor_open": bool((status_byte >> 2) & 1),
            "wired_door_sensor_connected": bool(status_byte & 1),
            "battery_invalid": bool((status_byte >> 4) & 1),
        }
        if len(d) >= 14:
            result["wakeup_voltage"] = int(d[10:12], 16) + int(d[12:14], 16) * 256
        if len(d) >= 18:
            result["start_voltage"] = int(d[14:16], 16) + int(d[16:18], 16) * 256
        if len(d) >= 36:
            result["auto_unlock_delay_s"] = int(d[32:34], 16) + int(d[34:36], 16) * 256
        if len(d) >= 38:
            # QueryLockStatusCmd: lockType = m86670y(data[36:38]) — a plain byte.
            # Selects the command format for subsequent lock/unlock frames.
            result["lock_type"] = int(d[36:38], 16)
        if len(d) >= 54:
            # QueryLockStatusCmd stores data[38:54] as ble_aes_random_numbers_1062,
            # keyed by lock uuid, and replays it as the nonce in the next command.
            result["ble_nonce"] = d[38:54].upper()
        if len(d) >= 62:
            result["ble_module_version"] = d[54:62]
        return result
    except Exception:
        _LOGGER.exception("Failed to parse ACK: %s", ack_hex[:60])
        return {}


# ── Cached status bit masks (HubCacheStatusData) ─────────────────────────────
# bit 0 (=1)   LOCK_STATUS_BIT  : 0=locked, 1=unlocked
# bit 1 (=2)   HAS_WIRED_DS_BIT : wired door sensor present
# bit 2 (=4)   WIRED_DS_STATUS  : wired door sensor open
# bit 3 (=8)   HAS_RF_DS_BIT    : RF door sensor present
# bit 4 (=16)  RF_DS_STATUS     : RF door sensor open
# bit 7 (=128) LOW_BAT_BIT      : low battery


def parse_cached_status(sts: int) -> dict[str, Any]:
    """Parse the `sts` integer from lock/cachedstatus/get response."""
    wired = bool(sts & 2)
    rf = bool(sts & 8)
    if wired:
        door_open: bool | None = bool(sts & 4)
    elif rf:
        door_open = bool(sts & 16)
    else:
        door_open = None
    return {
        "is_locked": not bool(sts & 1),
        "low_battery": bool(sts & 128),
        "door_sensor_open": door_open,
        "wired_door_sensor_connected": wired,
        "rf_door_sensor_connected": rf,
        "secure_lock_mode": bool(sts & 64),
    }


# ── Error codes ───────────────────────────────────────────────────────────────

_COD_MEANINGS = {
    "200": "OK",
    "900": "hub system error, or hub firmware predates this endpoint",
    "901": "lock not found for this account",
    "909": "request could not be parsed (para not DES3-encrypted?)",
    "910": "para not encrypted",
    "920": "endpoint rejected the request",
    "930": "hub/Secure LINK not associated with this lock — check the lock is "
           "bound to a hub in the Lockly app; WiFi-native locks with no hub "
           "cannot use this endpoint",
    "931": "Secure LINK already bound to another account",
    "932": "Secure LINK does not exist",
    "938": "ID format error",
    "942": "hub timed out relaying to the lock (out of BLE range?) — transient",
    "943": "hub offline",
    "990": "general server error",
}


def describe_cod(cod: str) -> str:
    """Human-readable meaning for a Lockly API response code."""
    return _COD_MEANINGS.get(str(cod), "unknown code")


def sha256_hex(password: str) -> str:
    """SHA256Util.m87491b: SHA-256 of password string → lowercase hex."""
    return hashlib.sha256(password.encode()).hexdigest()


def _headers(jwt: str | None = None) -> dict:
    h = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": API_USER_AGENT,
        "Accept-Encoding": "gzip",
    }
    if jwt:
        h["Authorization"] = f"Bearer {jwt}"
    return h


# ── HTTP API calls ─────────────────────────────────────────────────────────────

async def api_login(session: aiohttp.ClientSession, email: str, password: str) -> str | None:
    """Login and return JWT token, or None on failure.

    Password is SHA-256 hashed before sending (per LoginActivity line 587).
    JWT returned in HTTP response Authorization header (TokenRenewInterceptor).
    """
    req_json = json.dumps({"acct": email, "pw": sha256_hex(password)}, separators=(",", ":"))
    para = rsa_encrypt_para(req_json)
    try:
        async with session.post(
            API_BASE + "login",
            json={**COMMON_BODY, "para": para},
            headers=_headers(),
        ) as resp:
            body = await resp.json(content_type=None)
            if str(body.get("cod")) != "200":
                _LOGGER.error("Login failed: cod=%s", body.get("cod"))
                return None
            jwt = resp.headers.get("Authorization", "")
            if jwt.startswith("Bearer "):
                jwt = jwt[7:]
            if not jwt:
                _LOGGER.error("Login succeeded but no JWT in response headers")
                return None
            return jwt
    except Exception:
        _LOGGER.exception("Login request failed")
        return None


async def api_get_devices(
    session: aiohttp.ClientSession, jwt: str, email: str
) -> tuple[list[dict], bytes | None]:
    """Fetch device list and DES3 key via qrylknew.

    Returns (locks_list, des3_key_bytes) or ([], None) on failure.
    """
    req_json = json.dumps({"acct": email}, separators=(",", ":"))
    para = rsa_encrypt_para(req_json)
    try:
        async with session.post(
            API_BASE + "qrylknew",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            if str(body.get("cod")) != "200":
                _LOGGER.error("qrylknew failed: cod=%s", body.get("cod"))
                return [], None

            server_key_str = rsa_decrypt_key(body["key"])
            des3_key = des3_key_from_server_key(server_key_str)

            locks = []
            for dl_entry in body.get("dl", []):
                try:
                    pt = des3_decrypt(des3_key, dl_entry)
                    lock = json.loads(pt.rstrip(b"\x00"))
                    locks.append(lock)
                except Exception:
                    _LOGGER.exception("Failed to decrypt lock entry")

            return locks, des3_key
    except Exception:
        _LOGGER.exception("qrylknew request failed")
        return [], None


async def api_cached_status(
    session: aiohttp.ClientSession,
    jwt: str,
    des3_key: bytes,
    email: str,
    lock: dict,
) -> dict[str, Any] | None:
    """Query lock status from the server cache — NO physical device contact, NO beep.

    POST lock/cachedstatus/get  →  {"data": {"addr": "...", "sts": <int>, "time": <long>}}
    Status bits parsed via parse_cached_status().

    Parameters are DES3-encrypted in the 'para' field, matching the pattern used by
    all other post-auth endpoints (senddata, getstatus, etc.).
    """
    lock_id = lock["ID"]
    req = {"acct": email, "dv": lock_id, "hubid": lock.get("hubid", "")}
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "lock/cachedstatus/get",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            cod = str(body.get("cod"))
            if cod != "200":
                # Logged at the same level as the senddata failure below: when
                # this is silent, user reports quote only the senddata line and
                # understate how much is actually failing.
                _LOGGER.warning(
                    "cachedstatus failed: cod=%s lock=%s hubid=%s (%s)",
                    cod, lock_id, lock.get("hubid") or "(empty)", describe_cod(cod),
                )
                return None
            data = body.get("data") or {}
            sts = data.get("sts")
            if sts is None:
                _LOGGER.warning("cachedstatus: no 'sts' in data for lock %s", lock_id)
                return None
            return {**parse_cached_status(int(sts)), "cache_time": data.get("time")}
    except Exception:
        _LOGGER.exception("cachedstatus request failed for lock %s", lock_id)
        return None


async def api_query_lock_status(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
) -> dict[str, Any] | None:
    """Query lock status via senddata. Returns parsed status dict or None."""
    mc = str(lock["mc"])
    uuid = lock["ID"]
    cmd_hex = build_query_status_cmd(mc, uuid)

    req = {
        "acct": email,
        "hubid": lock.get("hubid", ""),
        "dv": lock["ID"],
        "cmd": cmd_hex,
        "mdna": lock.get("iotdm", ""),
    }
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "senddata",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
            timeout=aiohttp.ClientTimeout(total=SENDDATA_TIMEOUT),
        ) as resp:
            body = await resp.json(content_type=None)
            cod = str(body.get("cod"))
            if cod != "200" or "ACK" not in body:
                _LOGGER.warning(
                    "senddata status query failed: cod=%s lock=%s hubid=%s (%s)",
                    cod, lock.get("blename"), lock.get("hubid") or "(empty)",
                    describe_cod(cod),
                )
                return None
            parsed = parse_ack(body["ACK"], mc, uuid)
            if parsed and "battery_invalid" in parsed:
                parsed.setdefault("low_battery", parsed["battery_invalid"])
            return parsed
    except Exception:
        _LOGGER.exception("senddata request failed for lock %s", lock.get("blename"))
        return None


# Lock-side error codes, from Cmd.getErrorInfo() and res/values/strings.xml.
# These appear as a single unencrypted byte at ack_hex[16:18] when the lock
# rejects a command.
_BLE_ERRORS = {
    "F0": "too many 4-digit access codes (max 10; use 5-8 digits)",
    "F1": "battery too low for an OTA update",
    "F5": "Bluetooth connection problem — try again later",
    "F8": "cannot change the password",
    "F9": "this credential's valid time period has not started yet",
    "FA": "lock reported a system error",
    "FB": "a maximum has been reached",
    "FD": "this door code has been used before",
    "FF": "wrong password — the lock rejected the credential in the command",
}


# Access-log event types.  The app resolves these through a two-stage string
# switch — the code maps to an index, and the index maps to a label hundreds of
# lines away — so the code and its meaning are never adjacent in the source.
#
# This table is as complete as the app itself.  The label switch stops at index
# 31, and higher codes (42 and up, which these locks emit often) map to indices
# beyond that and fall through to a default branch which renders them
# generically.  So there is no per-code label to recover for them: the app does
# not distinguish them either, and reporting the raw number is more honest than
# inventing a name.
#
# Note this identifies *how* the lock was opened, not which credential type was
# used: fingerprint and RFID are distinguished via separate sensor lists that
# these locks do not expose.
_OPEN_TYPE_LABELS = {
    "2": "keypad",
    "4": "physical key",
    "6": "lock clock updated",
    "7": "alarm",
    "8": "low battery",
    "9": "emergency code",
    "16": "guest code",
    "17": "guest one-time code",
    "21": "one-time code",
    "31": "long-term guest one-time code",
}


def describe_open_type(code: str | None) -> str:
    """Readable name for an access-log event type, or the raw code if unknown."""
    if code is None:
        return "unknown"
    return _OPEN_TYPE_LABELS.get(str(code), f"type {code}")


def describe_ble_error(code: str) -> str:
    """Human-readable meaning for a lock-side BLE error byte."""
    return _BLE_ERRORS.get(str(code).upper(), "unknown lock error")


async def api_get_heartbeat(
    session: aiohttp.ClientSession,
    jwt: str,
    des3_key: bytes,
    device_id: str,
    model: str = "Pixel 8 Pro",
) -> dict[str, Any] | None:
    """Fetch the account's MQTT push configuration.

    ``POST getHeartbeatTime`` returns ``{heartbeat, mqttConfigs}`` where
    mqttConfigs is ``{clientId, host, port}`` (HeartbeatTimeApiResponse /
    MqttConfigApiResponse).  The request carries the *client's* deviceId and
    model, not a lock, which is why this looks like the app's own push channel
    rather than per-lock configuration.

    ``clientId`` is the only MQTT client id the API exposes, and
    MqttConnectionOption can build its username as ``{user_client_id}_{email}``
    — so this is the missing half of the broker's subscription authorisation.

    Returns the parsed config, or None on failure.
    """
    req = {"deviceId": device_id, "model": model}
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "getHeartbeatTime",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            cod = str(body.get("cod"))
            if cod != "200":
                _LOGGER.warning(
                    "getHeartbeatTime failed: cod=%s (%s)", cod, describe_cod(cod)
                )
                return None
            cfg = body.get("mqttConfigs") or {}
            result = {
                "heartbeat": body.get("heartbeat"),
                "client_id": cfg.get("clientId"),
                "host": cfg.get("host"),
                "port": cfg.get("port"),
            }
            _LOGGER.debug("getHeartbeatTime: %s", result)
            return result
    except Exception:
        _LOGGER.exception("getHeartbeatTime request failed")
        return None


async def api_query_passwords(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
    nonce: str | None = None,
    caps: LockCapabilities | None = None,
    max_pages: int = 16,
) -> list[dict] | None:
    """Read the lock's credential list via QueryPwd147 (0x93).

    The cloud's ``hc`` field is only a copy of the host password, and the app
    updates its own copy locally whenever the host code is changed on the lock
    (BindLockManager after SetHostPwdCmd).  So ``hc`` can fall behind the lock.
    This asks the lock directly, the way the app does.

    Returns the credential entries, or None if the query failed.  The host
    password is the entry whose ``pwd_id`` is 0.
    """
    mc = str(lock["mc"])
    uuid = lock["ID"]
    five_hundred = bool((caps or DEFAULT_CAPABILITIES).supports_500_group_password)

    entries: list[dict] = []
    position = 0
    for _ in range(max_pages):
        cmd_hex = build_query_pwd_cmd(mc, uuid, position=position, nonce=nonce)
        req = {
            "acct": email,
            "hubid": lock.get("hubid", ""),
            "dv": uuid,
            "cmd": cmd_hex,
            "mdna": lock.get("iotdm", ""),
        }
        para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
        try:
            async with session.post(
                API_BASE + "senddata",
                json={**COMMON_BODY, "para": para},
                headers=_headers(jwt),
                timeout=aiohttp.ClientTimeout(total=SENDDATA_TIMEOUT),
            ) as resp:
                body = await resp.json(content_type=None)
                cod = str(body.get("cod"))
                if cod != "200" or "ACK" not in body:
                    _LOGGER.warning(
                        "query passwords failed: cod=%s lock=%s page=%d (%s)",
                        cod, lock.get("blename"), position, describe_cod(cod),
                    )
                    return None
                page = parse_pwd_list_ack(body["ACK"], mc, uuid, five_hundred)
                if page is None:
                    return None
        except Exception:
            _LOGGER.exception(
                "query passwords request failed for lock %s", lock.get("blename")
            )
            return None

        entries = dedupe_credentials(entries + (page.get("entries") or []))

        # The lock states how many credentials it holds; stop once we have them
        # all rather than trusting the page counters.
        total = page.get("total") or 0
        if page.get("is_end", True) or (total and len(entries) >= total):
            break
        position = int(page.get("cur_page", position)) + 1

    return entries


def build_query_log_cmd(
    master_code: str,
    uuid: str,
    nonce: str | None = None,
    caps: LockCapabilities | None = None,
) -> str:
    """Build a SyncUnlockRecord frame — reads the access log from the lock.

    The cloud's getlkhist only serves what was uploaded historically, which on
    the hardware tested here is either nothing or records years old.  The app
    reads current activity from the lock instead, which is what this does.

    Layout is the same shape as the other queries:

        cmd + mc_len + enc_mc + nonce

    The command code depends on the hardware — 0x53 for attendance locks, 0x78
    for the wider "log 120" format, 0x04 otherwise.
    """
    caps = caps or DEFAULT_CAPABILITIES
    enc_mc = encrypt_master_code(master_code, uuid)
    raw = _assemble_fields(
        caps.log_cmd_code,
        f"{len(enc_mc) // 2:d}",
        enc_mc,
        (nonce or "").upper(),
    )
    return _aes_wrap(raw, derive_aes_key(master_code, uuid))


def _decode_packed_datetime(hex12: str) -> int | None:
    """Decode a 6-byte packed yyMMddHHmmss timestamp to epoch milliseconds.

    Each byte holds one component as hex digits that read as decimal — 0x25 is
    the year 25, not 37.  This is the inverse of the encoding used when building
    a status query, and DataUtils.m86669x in the app.

    Returned in the local timezone, since the lock keeps local wall-clock time.
    """
    if len(hex12) < 12:
        return None
    try:
        parts = [int(hex12[i:i + 2], 16) for i in range(0, 12, 2)]
    except ValueError:
        return None
    year, month, day, hour, minute, second = parts
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour < 24 and minute < 60 and second < 60):
        return None
    try:
        stamp = datetime(2000 + year, month, day, hour, minute, second)
    except ValueError:
        return None
    return int(stamp.timestamp() * 1000)


def parse_log_ack(
    ack_hex: str,
    master_code: str,
    uuid: str,
    caps: LockCapabilities | None = None,
) -> list[dict] | None:
    """Parse a SyncUnlockRecord response into access-log records.

    After the AES payload is decrypted, the first byte is a header and the rest
    is a flat array of fixed-width records (SyncUnlockRecordCmd.getAllLockRecord):

        date(6B) | open_type(1B) | slot(2B) | record_id(2B)

    on the wide formats, or a 1-byte slot on the legacy one.  A trailing partial
    record is ignored, as the app does.
    """
    caps = caps or DEFAULT_CAPABILITIES
    width = caps.log_record_chars
    h = ack_hex.upper()
    try:
        payload = bytes.fromhex(h[16:-2])
        if len(payload) == 0 or len(payload) % 16 != 0:
            code = h[16:18]
            _LOGGER.debug(
                "query log rejected: %s — %s", code, describe_ble_error(code)
            )
            return None
        d = AES.new(derive_aes_key(master_code, uuid), AES.MODE_ECB).decrypt(payload).hex().upper()

        body = d[2:]                      # first byte is a header
        usable = len(body) - (len(body) % width)
        records: list[dict] = []
        for start in range(0, usable, width):
            rec = body[start:start + width]
            timestamp = _decode_packed_datetime(rec[0:12])
            if timestamp is None:
                # Zero padding at the end of the block decodes as an impossible
                # date; that marks the end of the real records.
                break
            if width == LOG_RECORD_CHARS_WIDE:
                slot = int(rec[14:16], 16) + int(rec[16:18], 16) * 256
                record_id = int(rec[18:20], 16) + int(rec[20:22], 16) * 256
                no_credential = slot == 0xFFFF
            else:
                slot = int(rec[14:16], 16)
                record_id = int(rec[16:18], 16) + int(rec[18:20], 16) * 256
                no_credential = slot == 0xFF
            if no_credential:
                # An all-ones slot is the "no credential" sentinel, used for
                # events that are not somebody unlocking — auto-lock, door
                # events and similar.  The cloud log uses the same convention
                # (pid 255 in its one-byte form).
                slot = None
            records.append({
                "tm": timestamp,
                "co": str(int(rec[12:14], 16)),  # open type, as getlkhist reports it
                "pid": slot,
                "id": record_id,
                "na": "",
            })
        return records
    except Exception:
        _LOGGER.exception("Failed to parse access log ACK: %s", ack_hex[:60])
        return None


async def api_query_lock_log(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
    nonce: str | None = None,
    caps: LockCapabilities | None = None,
) -> list[dict] | None:
    """Read the access log directly from the lock via senddata."""
    mc = str(lock["mc"])
    uuid = lock["ID"]
    cmd_hex = build_query_log_cmd(mc, uuid, nonce, caps)
    req = {
        "acct": email,
        "hubid": lock.get("hubid", ""),
        "dv": uuid,
        "cmd": cmd_hex,
        "mdna": lock.get("iotdm", ""),
    }
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "senddata",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
            timeout=aiohttp.ClientTimeout(total=SENDDATA_TIMEOUT),
        ) as resp:
            body = await resp.json(content_type=None)
            cod = str(body.get("cod"))
            if cod != "200" or "ACK" not in body:
                _LOGGER.warning(
                    "query lock log failed: cod=%s lock=%s (%s)",
                    cod, lock.get("blename"), describe_cod(cod),
                )
                return None
            return parse_log_ack(body["ACK"], mc, uuid, caps)
    except Exception:
        _LOGGER.exception("query lock log failed for lock %s", lock.get("blename"))
        return None


def _digits_to_packed_hex(digits: str) -> str:
    """Encode a decimal digit string as one byte per pair (DataUtils.m86646a).

    Each two decimal digits become the byte whose hex representation reads as
    those digits — "26" becomes 0x1A.  This is the same encoding used for the
    timestamp in a status query.
    """
    return "".join(f"{int(digits[i:i + 2]):02x}" for i in range(0, len(digits), 2))


def _paging_bounds(epoch_ms: int | None) -> tuple[str, str]:
    """Encode one end of the paged-log date range.

    Returns (date, time) — 3 bytes of yyMMdd and 5 bytes of yyMMddHHmm.  A
    non-positive bound becomes the "unlimited" sentinels, which is how the app
    asks for an open-ended range.

    The split into a 6-digit and a 10-digit field follows getNum6StringByLong /
    getNum10StringByLong; the exact field meanings are inferred from their
    lengths, so this is validated against a lock whose log we can already read
    before being relied on.
    """
    if not epoch_ms or epoch_ms <= 0:
        return PAGING_DATE_UNLIMITED, PAGING_TIME_UNLIMITED
    stamp = datetime.fromtimestamp(epoch_ms / 1000)
    return (
        _digits_to_packed_hex(stamp.strftime("%y%m%d")),
        _digits_to_packed_hex(stamp.strftime("%y%m%d%H%M")),
    )


def build_paging_log_cmd(
    master_code: str,
    uuid: str,
    index: int = 0,
    start_ms: int | None = None,
    end_ms: int | None = None,
    nonce: str | None = None,
    caps: LockCapabilities | None = None,
) -> str:
    """Build a PagingLogCmd frame — the paged, date-bounded access-log query.

    Where SyncUnlockRecord returns the whole log in one large response, this
    asks for a bounded window one page at a time, which is what makes it usable
    on locks whose BLE link cannot carry the bulk transfer.

    Layout (PagingLogCmd.getData):

        cmd | mc_len | enc_mc | start_date | end_date | index | start_time |
        end_time | nonce
    """
    caps = caps or DEFAULT_CAPABILITIES
    enc_mc = encrypt_master_code(master_code, uuid)
    start_date, start_time = _paging_bounds(start_ms)
    end_date, end_time = _paging_bounds(end_ms)
    raw = _assemble_fields(
        caps.paging_log_cmd_code,
        f"{len(enc_mc) // 2:d}",
        enc_mc,
        start_date,
        end_date,
        f"{index & 0xFF:02x}{(index >> 8) & 0xFF:02x}",  # 2-byte little endian
        start_time,
        end_time,
        (nonce or "").upper(),
    )
    return _aes_wrap(raw, derive_aes_key(master_code, uuid))


def parse_paging_log_ack(
    ack_hex: str,
    master_code: str,
    uuid: str,
) -> dict[str, Any] | None:
    """Parse a PagingLogCmd response.

    Header is total, current and the record count in this page, each a 2-byte
    little-endian value, followed by fixed-width records:

        date(6B) | open_type(1B) | slot(4B LE) | record_id(2B LE)
    """
    h = ack_hex.upper()
    try:
        payload = bytes.fromhex(h[16:-2])
        if len(payload) == 0 or len(payload) % 16 != 0:
            code = h[16:18]
            _LOGGER.debug(
                "paged log rejected: %s — %s", code, describe_ble_error(code)
            )
            return None
        d = AES.new(derive_aes_key(master_code, uuid), AES.MODE_ECB).decrypt(payload).hex().upper()
        if len(d) < 12:
            return None

        def le16(chunk: str) -> int:
            return int(chunk[0:2], 16) + int(chunk[2:4], 16) * 256

        total = le16(d[0:4])
        current = le16(d[4:8])
        count = le16(d[8:12])

        body = d[12:]
        records: list[dict] = []
        for i in range(count):
            start = i * PAGING_LOG_RECORD_CHARS
            rec = body[start:start + PAGING_LOG_RECORD_CHARS]
            if len(rec) < PAGING_LOG_RECORD_CHARS:
                break
            timestamp = _decode_packed_datetime(rec[0:12])
            if timestamp is None:
                break
            slot = sum(int(rec[14 + n * 2:16 + n * 2], 16) << (8 * n) for n in range(4))
            records.append({
                "tm": timestamp,
                "co": str(int(rec[12:14], 16)),
                "pid": None if slot in (0xFF, 0xFFFF, 0xFFFFFFFF) else slot,
                "id": le16(rec[22:26]),
                "na": "",
            })
        return {
            "records": records,
            "total": total,
            "current": current,
            "is_end": current >= total,
        }
    except Exception:
        _LOGGER.exception("Failed to parse paged log ACK: %s", ack_hex[:60])
        return None


async def api_query_lock_log_paged(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
    start_ms: int | None = None,
    end_ms: int | None = None,
    nonce: str | None = None,
    caps: LockCapabilities | None = None,
    max_pages: int = 8,
) -> list[dict] | None:
    """Read the access log a page at a time, bounded by a date range.

    Preferred over the bulk read on locks whose BLE link cannot carry a large
    response — the bulk form returns the whole log at once and times out, where
    a bounded page is small enough to get through.
    """
    mc = str(lock["mc"])
    uuid = lock["ID"]
    records: list[dict] = []
    index = 0

    for _ in range(max_pages):
        cmd_hex = build_paging_log_cmd(mc, uuid, index, start_ms, end_ms, nonce, caps)
        req = {
            "acct": email,
            "hubid": lock.get("hubid", ""),
            "dv": uuid,
            "cmd": cmd_hex,
            "mdna": lock.get("iotdm", ""),
        }
        para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
        try:
            async with session.post(
                API_BASE + "senddata",
                json={**COMMON_BODY, "para": para},
                headers=_headers(jwt),
                timeout=aiohttp.ClientTimeout(total=SENDDATA_TIMEOUT),
            ) as resp:
                body = await resp.json(content_type=None)
                cod = str(body.get("cod"))
                if cod != "200" or "ACK" not in body:
                    _LOGGER.debug(
                        "paged log failed: cod=%s lock=%s page=%d (%s)",
                        cod, lock.get("blename"), index, describe_cod(cod),
                    )
                    return records or None
                page = parse_paging_log_ack(body["ACK"], mc, uuid)
                if page is None:
                    return records or None
        except Exception:
            _LOGGER.exception("paged log request failed for %s", lock.get("blename"))
            return records or None

        records.extend(page["records"])
        _LOGGER.debug(
            "Lockly paged log: %s page %d — %d record(s), %d/%d",
            lock.get("blename") or uuid, index,
            len(page["records"]), page["current"], page["total"],
        )
        if page["is_end"] or not page["records"]:
            break
        index += 1

    return records


def dedupe_credentials(entries: list[dict]) -> list[dict]:
    """Keep the first entry per credential slot, preserving order.

    A lock that returns its whole credential list in one response can still
    report page counters that read as "there is more".  Following them
    re-requests the same page, so the same credentials arrive twice.  The slot
    is unique per credential, so it is the right key to collapse on.
    """
    seen: set = set()
    unique: list[dict] = []
    for entry in entries:
        slot = entry.get("pwd_id")
        if slot in seen:
            continue
        seen.add(slot)
        unique.append(entry)
    return unique


def host_password_from(entries: list[dict]) -> str | None:
    """Pick the host credential out of a queried list.

    QueryPwdUtil.m87342t returns the entry whose pwd_id is 0.
    """
    for entry in entries or []:
        if entry.get("pwd_id") == 0:
            return entry.get("password") or None
    return None


def _ack_reports_success(ack_hex: str, master_code: str, uuid: str) -> tuple[bool, str]:
    """Decide whether a lock/unlock ACK means the lock actually acted.

    ``cod=200`` only means the cloud accepted the request and the hub relayed it.
    The lock's own verdict is in the ACK frame, so a NACK must not be reported to
    Home Assistant as a successful unlock.

    A rejection comes back as a short, unencrypted frame whose cmd-type byte is
    ``0C`` rather than ``0A``, followed by one error byte (``Cmd.getErrorCode``
    reads exactly this offset). A success carries an AES-encrypted status block.

    Returns (accepted, detail).
    """
    if not ack_hex:
        return False, "no ACK returned"
    h = ack_hex.upper()
    try:
        payload = bytes.fromhex(h[16:-2])
        if len(payload) == 0:
            return False, "lock returned an empty ACK"
        if len(payload) % 16 != 0:
            # Short frame = rejection; the first payload byte is the error code.
            code = h[16:18]
            return False, f"lock rejected the command: {code} — {describe_ble_error(code)}"
        d = AES.new(derive_aes_key(master_code, uuid), AES.MODE_ECB).decrypt(payload).hex()
        status = int(d[8:10], 16) if len(d) >= 10 else None
        return True, f"lock ACK status=0x{status:02X}" if status is not None else "lock ACK"
    except Exception:
        return False, f"unparseable ACK {ack_hex[:24]}"


async def _api_send_directive(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
    directive: str,
    cmd_hex: str,
) -> bool:
    """Send a lock/unlock directive via senddata.

    Returns True only when the cloud accepted the request *and* the lock's ACK
    frame parses as an acknowledgement.
    """
    hub_id = str(lock.get("hubid") or "")
    if not hub_id:
        _LOGGER.error(
            "Lock %s has no hub (hubid is empty) — the senddata endpoint relays "
            "commands through a Lockly hub and cannot control this lock. "
            "WiFi-native locks are not yet supported; see issue #2.",
            lock.get("blename") or lock.get("ID"),
        )
        return False

    req = {
        "acct": email,
        "hubid": hub_id,
        "dv": lock["ID"],
        "cmd": cmd_hex,
        "mdna": lock.get("iotdm", ""),
        "directive": directive,
    }
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "senddata",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
            timeout=aiohttp.ClientTimeout(total=SENDDATA_TIMEOUT),
        ) as resp:
            body = await resp.json(content_type=None)
            cod = str(body.get("cod"))
            ack = body.get("ACK", "")
            _LOGGER.debug(
                "senddata directive=%s cod=%s ack=%s lock=%s",
                directive, cod, ack or "(none)", lock.get("blename"),
            )
            if cod != "200":
                _LOGGER.warning(
                    "senddata %s failed: cod=%s lock=%s (%s)",
                    directive, cod, lock.get("blename") or lock["ID"], describe_cod(cod),
                )
                return False
            accepted, detail = _ack_reports_success(ack, str(lock["mc"]), lock["ID"])
            if not accepted:
                _LOGGER.warning(
                    "senddata %s: cloud accepted (cod=200) but lock %s did not — %s",
                    directive, lock.get("blename") or lock["ID"], detail,
                )
            return accepted
    except Exception:
        _LOGGER.exception(
            "senddata directive=%s failed for lock %s", directive, lock.get("blename")
        )
        return False


async def api_unlock(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
    nonce: str | None = None,
    caps: LockCapabilities | None = None,
    lock_pwd_override: str | None = None,
) -> bool:
    """Send unlock command. Returns True if the lock acknowledged."""
    mc = str(lock["mc"])
    lock_pwd = lock_pwd_override if lock_pwd_override is not None else str(lock.get("hc") or "")
    return await _api_send_directive(
        session, jwt, email, des3_key, lock, "unlock",
        build_unlock_cmd(mc, lock["ID"], lock_pwd, nonce, caps=caps),
    )


async def api_lock(
    session: aiohttp.ClientSession,
    jwt: str,
    email: str,
    des3_key: bytes,
    lock: dict,
    nonce: str | None = None,
    caps: LockCapabilities | None = None,
    lock_pwd_override: str | None = None,
) -> bool:
    """Send lock command. Returns True if the lock acknowledged."""
    mc = str(lock["mc"])
    lock_pwd = lock_pwd_override if lock_pwd_override is not None else str(lock.get("hc") or "")
    return await _api_send_directive(
        session, jwt, email, des3_key, lock, "lock",
        build_lock_cmd(mc, lock["ID"], lock_pwd, nonce, caps=caps),
    )


# ── Access log ────────────────────────────────────────────────────────────────

async def api_get_lock_history(
    session: aiohttp.ClientSession,
    jwt: str,
    des3_key: bytes,
    email: str,
    lock_id: str,
    since_ms: int,
) -> tuple[list[dict], int] | None:
    """Fetch access log events since since_ms (epoch ms).

    Returns (events, last_sync_time_ms) or None on failure.
    events is the raw 'el' list from HistoryQueryBean.
    last_sync_time_ms should be saved and passed back as since_ms next call.
    Response field names (el, LAST_EVENT_SYNC_TIME) come from HistoryQueryBean
    in the APK — validate against live hardware on first deploy.
    """
    req = {"acct": email, "ID": lock_id, "time": str(since_ms)}
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "getlkhist",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            if str(body.get("cod")) != "200":
                _LOGGER.debug("getlkhist failed: cod=%s lock=%s", body.get("cod"), lock_id)
                return None
            events = body.get("el") or []
            last_sync = body.get("LAST_EVENT_SYNC_TIME") or since_ms
            return list(events), int(last_sync)
    except Exception:
        _LOGGER.exception("getlkhist request failed for lock %s", lock_id)
        return None


# ── Guest / access user management ───────────────────────────────────────────

async def api_list_guests(
    session: aiohttp.ClientSession,
    jwt: str,
    des3_key: bytes,
    lock_id: str,
    admin_acu_id: int,
) -> list[dict] | None:
    """Return guest credential list for a lock, or None on failure.

    Endpoint: POST acu/crdntl/list
    Each item contains: userAcuId, name, pw (PIN), tp (type), startTime,
    endTime, acuStatus ("Y"/"S"), guestType.
    """
    req = {"dv": lock_id, "adminAcuId": admin_acu_id}
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "acu/crdntl/list",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            _LOGGER.debug("acu/crdntl/list raw response: %s", body)
            if str(body.get("cod")) != "200":
                _LOGGER.error("acu/crdntl/list failed: cod=%s lock=%s", body.get("cod"), lock_id)
                return None
            return body.get("acuMediumList") or []
    except Exception:
        _LOGGER.exception("acu/crdntl/list failed for lock %s", lock_id)
        return None


async def api_add_guest(
    session: aiohttp.ClientSession,
    jwt: str,
    des3_key: bytes,
    lock_id: str,
    name: str,
    passcode: str,
    start_ms: int,
    end_ms: int,
) -> dict | None:
    """Create a time-limited guest user with a PIN code.

    Returns response body dict (contains userAcuId) on success, None on failure.
    Endpoint: POST acu/save

    WARNING: whether the passcode auto-activates on the lock hardware after this
    call is untested. If the guest code does not work physically, call
    api_activate_passcode() (see stub below) after this returns successfully.
    """
    guest_body = {
        "startTime": start_ms,
        "endTime": end_ms,
        "weekData": 0,
        "pw": passcode,
        "pid": 1,
        "pwStatus": "Y",
        "subadm": "false",
        "oacpriv": "false",
    }
    req = {
        "dv": lock_id,
        "name": name,
        "type": "GUEST",
        "userAcuId": 0,
        "acuStatus": "Y",
        "timeType": "MORE_LIMIT",
        "isRetry": False,
        "multipleVerific": 0,
        "acuGuest": guest_body,
    }
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "acu/save",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            _LOGGER.debug("acu/save raw response: %s", body)
            if str(body.get("cod")) != "200":
                _LOGGER.error("acu/save failed: cod=%s lock=%s", body.get("cod"), lock_id)
                return None
            _LOGGER.info(
                "Guest '%s' created for lock %s — verify PIN activates on lock hardware",
                name, lock_id,
            )
            return body
    except Exception:
        _LOGGER.exception("acu/save failed for lock %s", lock_id)
        return None


async def api_delete_guest(
    session: aiohttp.ClientSession,
    jwt: str,
    des3_key: bytes,
    lock_id: str,
    user_acu_id: int,
    admin_acu_id: int,
) -> bool:
    """Delete a guest user by userAcuId. Returns True on success."""
    req = {
        "dv": lock_id,
        "userAcuId": user_acu_id,
        "adminAcuId": admin_acu_id,
    }
    para = des3_encrypt(des3_key, json.dumps(req, separators=(",", ":")))
    try:
        async with session.post(
            API_BASE + "acu/delete",
            json={**COMMON_BODY, "para": para},
            headers=_headers(jwt),
        ) as resp:
            body = await resp.json(content_type=None)
            if str(body.get("cod")) != "200":
                _LOGGER.error("acu/delete failed: cod=%s lock=%s", body.get("cod"), lock_id)
                return False
            return True
    except Exception:
        _LOGGER.exception("acu/delete failed for lock %s", lock_id)
        return False


# async def api_activate_passcode(
#     session, jwt, des3_key, lock_id: str, user_acu_id: int, pwd_id: int, admin_acu_id: int
# ) -> bool:
#     """POST acu/crdntl/pwList/active — pushes a pending PIN to the lock hardware.
#     para: {"dv": lock_id, "isAdmin": False,
#            "pwList": [{"userId": user_acu_id, "pid": pwd_id, "adminAcuId": admin_acu_id}]}
#     Call after api_add_guest() if the passcode does not auto-activate on the lock.
#     """
