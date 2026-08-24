"""Offline checks for the Lockly BLE frame builders.

These assert the exact plaintext layout derived from the Lockly app's
``NewUnlockCmd.getData`` / ``HexUtils.m86802c``.  They need no hardware and no
network, so they catch a regression in the frame before it ever reaches a lock.

Run inside the Home Assistant container:

    docker exec homeassistant python /config/test_frame.py
"""
from __future__ import annotations

import sys

from Crypto.Cipher import AES

from custom_components.lockly.api import (
    build_lock_cmd,
    build_query_status_cmd,
    build_unlock_cmd,
    crc8_lockly,
    derive_aes_key,
    encrypt_master_code,
    parse_ack,
)
from custom_components.lockly.capabilities import (
    LockCapabilities,
    resolve_capabilities,
)

# "Front Door" — one of the locks whose status queries are known to succeed.
MC = "59563738"
UUID = "280033003131470432353835"
HC = "980798"
NONCE = "02649931F6485436"

# Field offsets in hex characters within the decrypted plaintext.
_ACTION = slice(36, 38)
_STR3 = slice(38, 40)

_failures: list[str] = []


def check(label: str, actual, expected) -> None:
    if actual == expected:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}\n         expected: {expected}\n         actual:   {actual}")
        _failures.append(label)


def decrypt_frame(frame_hex: str, mc: str, uuid: str) -> str:
    """Recover the AES plaintext hex from a built BLE frame."""
    frame = bytes.fromhex(frame_hex)
    assert frame[:4] == bytes([0xA1, 0xB2, 0xC3, 0xD4]), "bad frame magic"
    total_len = frame[4] + frame[5] * 256
    assert total_len == len(frame), f"length field {total_len} != actual {len(frame)}"
    assert frame[-1] == crc8_lockly(frame[:-1]), "CRC-8 mismatch"
    payload = frame[6:-2]
    return AES.new(derive_aes_key(mc, uuid), AES.MODE_ECB).decrypt(payload).hex().upper()


def test_unlock_plaintext() -> None:
    """The field-by-field layout of a hub-relayed unlock."""
    print("unlock frame plaintext")
    enc_mc = encrypt_master_code(MC, UUID)
    plaintext = decrypt_frame(build_unlock_cmd(MC, UUID, HC, NONCE), MC, UUID)

    # 22 | 08 | enc_mc | 02 | hc expanded | 01 | 01 | 01 | nonce | zero padding
    expected = (
        "22"                    # NewUnlockCmd
        "08"                    # master code length in bytes
        + enc_mc                # master code XOR uuid
        + "02"                  # getUnLockType() = host
        + "090800070908"        # HexUtils.m86803d("980798") — the hc lock password
        + "01"                  # DataUtils.m86645J(pwdId=1)
        + "01"                  # str2 = unlock
        + "01"                  # str3 = 1, hub-relayed  <-- the field that was wrong
        + NONCE                 # stored nonce from the last status ACK
        + "00" * 4              # zero padding to the AES block
    )
    check("plaintext", plaintext, expected)
    check("length is 2 AES blocks", len(plaintext) // 2, 32)
    check("hc is present", "090800070908" in plaintext, True)
    # Field offsets in hex characters: cmd 0, mc_len 2, enc_mc 4, unlock_type 20,
    # hc 22, slot 34, action 36, str3 38, nonce 40.
    check("str3 is hub (01), not direct (00)", plaintext[_STR3], "01")
    check("nonce at expected offset", plaintext[40:56], NONCE)


def test_lock_differs_only_in_action() -> None:
    """Lock and unlock share the frame; only the action field changes."""
    print("lock vs unlock")
    unlock = decrypt_frame(build_unlock_cmd(MC, UUID, HC, NONCE), MC, UUID)
    lock = decrypt_frame(build_lock_cmd(MC, UUID, HC, NONCE), MC, UUID)
    diffs = [i for i, (a, b) in enumerate(zip(unlock, lock)) if a != b]
    check("exactly one differing hex position", len(diffs), 1)
    check("unlock action byte", unlock[_ACTION], "01")
    check("lock action byte", lock[_ACTION], "02")


def test_nonce_omitted_when_absent() -> None:
    """A missing nonce drops the field rather than sending zeros."""
    print("nonce omitted when unknown")
    without = decrypt_frame(build_unlock_cmd(MC, UUID, HC, None), MC, UUID)
    withnonce = decrypt_frame(build_unlock_cmd(MC, UUID, HC, NONCE), MC, UUID)
    check("shorter without nonce", len(without.rstrip("0")) < len(withnonce.rstrip("0")), True)
    check("nonce absent", NONCE in without, False)


def test_status_frame_unchanged() -> None:
    """The status query frame is known-good; the refactor must not alter it."""
    print("status query frame")
    enc_mc = encrypt_master_code(MC, UUID)
    plaintext = decrypt_frame(build_query_status_cmd(MC, UUID), MC, UUID)
    check("starts with 1E + len + enc_mc", plaintext[:4] + plaintext[4:20], "1E08" + enc_mc)
    check("length is 2 AES blocks", len(plaintext) // 2, 32)


def test_ack_parse_real_capture() -> None:
    """Parse a real ACK captured from this account's hardware."""
    print("ACK parsing (live capture)")
    ack = ("A1B2C3D429000A1E95A9B99DCBC5945E531B5EB4A643BA93BE5696D79B9791D9"
           "392AC7509E8BB800A2")
    parsed = parse_ack(ack, MC, UUID)
    check("is_locked", parsed.get("is_locked"), True)
    check("nonce extracted", parsed.get("ble_nonce"), NONCE)
    check("lock_type present", isinstance(parsed.get("lock_type"), int), True)
    volts = (parsed.get("wakeup_voltage") or 0) / 100
    check("battery voltage plausible for 4xAA", 3.5 < volts < 6.6, True)
    print(f"       lock_type={parsed.get('lock_type')} wakeup={volts:.2f}V")


def test_capabilities() -> None:
    """Frame variant selection per hardware generation."""
    print("capability dispatch")
    # PGD628FN — this account's locks.
    caps = resolve_capabilities({"mod": "PGD628FN"}, lock_type=21)
    check("PGD628FN uses 0x22", caps.cmd_code, "22")
    check("PGD628FN is not Vision", caps.is_vision, False)
    check("PGD628FN has no timestamp path", caps.supports_timestamp, False)
    # PGD728FG25 — the WiFi-native lock from issue #2.
    caps82 = resolve_capabilities({"mod": "PGD728FG25"}, lock_type=124)
    check("PGD728FG25 uses 0x52", caps82.cmd_code, "52")
    check("PGD728FG25 uses timestamp", caps82.supports_timestamp, True)
    # PGD728FN21 — the 500-group password layout.
    check("PGD728FN21 is 500-group",
          LockCapabilities(lock_type=129).supports_500_group_password, True)
    # PGI301 is an 0x52 lock explicitly excluded from the timestamp path.
    check("PGI301 excluded from timestamp",
          LockCapabilities(lock_type=121).supports_timestamp, False)
    # Unknown model falls back the way the app does.
    check("unknown model falls back to type 1",
          resolve_capabilities({"mod": "PGD999XX"}).lock_type, 1)
    check("fallback uses 0x22", resolve_capabilities({"mod": "PGD999XX"}).cmd_code, "22")


def main() -> int:
    for test in (
        test_unlock_plaintext,
        test_lock_differs_only_in_action,
        test_nonce_omitted_when_absent,
        test_status_frame_unchanged,
        test_ack_parse_real_capture,
        test_capabilities,
    ):
        test()
    print()
    if _failures:
        print(f"{len(_failures)} check(s) failed: {', '.join(_failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
