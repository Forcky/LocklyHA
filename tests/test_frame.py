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
    build_query_pwd_cmd,
    build_query_status_cmd,
    build_unlock_cmd,
    crc8_lockly,
    derive_aes_key,
    encrypt_master_code,
    host_password_from,
    parse_ack,
    parse_pwd_list_ack,
)
from custom_components.lockly import LocklyCoordinator
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
        + "00"                  # DataUtils.m86645J(pwdId=0) — host slot
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
    check("slot field is host slot 0", plaintext[34:36], "00")
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


def _wrap_response(plaintext_hex: str, cmd_type: str = "0A93") -> str:
    """Build a synthetic lock response frame around an AES-encrypted payload."""
    remainder = (len(plaintext_hex) // 2) % 16
    padded = plaintext_hex + ("" if remainder == 0 else "00" * (16 - remainder))
    enc = AES.new(derive_aes_key(MC, UUID), AES.MODE_ECB).encrypt(bytes.fromhex(padded))
    total = len(enc) + 8
    body = (
        bytes([0xA1, 0xB2, 0xC3, 0xD4])
        + bytes([total % 256, total // 256])
        + bytes.fromhex(cmd_type)
        + enc
    )
    return (body + bytes([crc8_lockly(body)])).hex().upper()


def test_query_pwd_frame() -> None:
    """The 0x93 credential-list request layout."""
    print("query passwords frame (0x93)")
    enc_mc = encrypt_master_code(MC, UUID)
    plaintext = decrypt_frame(build_query_pwd_cmd(MC, UUID, 0, NONCE), MC, UUID)
    expected = "93" + "08" + enc_mc + "00" + NONCE
    check("plaintext prefix", plaintext[:len(expected)], expected)
    # Page index is a hex field, so page 10 is "0a", not "10".
    page10 = decrypt_frame(build_query_pwd_cmd(MC, UUID, 10, NONCE), MC, UUID)
    check("page index is hex", page10[20:22], "0A")


def test_pwd_list_parsing() -> None:
    """Credential entries, including the host slot's missing schedule block."""
    print("password list parsing")
    host = "01" + "06" + "090800070908" + "00"          # slot 0, no schedule
    guest = "02" + "04" + "01020304" + "07" + "0" * 20  # slot 7, with schedule
    header = "00" + "01" + "01" + "02" + "02"           # ok, 1 page, page 1, 2 creds
    parsed = parse_pwd_list_ack(_wrap_response(header + host + guest), MC, UUID)

    check("parsed", parsed is not None, True)
    if not parsed:
        return
    check("total credentials", parsed["total"], 2)
    check("is_end", parsed["is_end"], True)
    check("entry count", len(parsed["entries"]), 2)
    check("host slot id", parsed["entries"][0]["pwd_id"], 0)
    check("host password decoded", parsed["entries"][0]["password"], "980798")
    check("guest slot id", parsed["entries"][1]["pwd_id"], 7)
    check("guest password decoded", parsed["entries"][1]["password"], "1234")
    check("host_password_from picks slot 0",
          host_password_from(parsed["entries"]), "980798")


def test_pwd_list_ignores_padding() -> None:
    """Zero padding must not become a phantom slot-0 credential."""
    print("password list padding")
    # One short entry, so the AES block leaves >10 bytes of zero padding.
    header = "00" + "01" + "01" + "01" + "01"
    entry = "01" + "04" + "01020304" + "00"
    parsed = parse_pwd_list_ack(_wrap_response(header + entry), MC, UUID)
    check("exactly one entry", len(parsed["entries"]) if parsed else -1, 1)
    check("password is real", parsed["entries"][0]["password"] if parsed else "", "1234")


def test_user_type_2_has_no_schedule() -> None:
    """user_type 2 skips the schedule block, like the host does.

    Getting this wrong swallows 10 bytes of the following entry and misaligns
    every credential after it — which is how a real lock reporting slots
    [0, 1, 7] came back as [0, 1] with duplicates.
    """
    print("user_type 2 skips schedule")
    host = "01" + "06" + "090800070908" + "00"           # slot 0, no schedule
    utype2 = "02" + "04" + "01020304" + "03"             # user_type 2, no schedule
    normal = "01" + "04" + "05060708" + "07" + "F" * 20  # slot 7, with schedule
    header = "00" + "01" + "01" + "03" + "03"
    parsed = parse_pwd_list_ack(_wrap_response(header + host + utype2 + normal), MC, UUID)

    check("parsed", parsed is not None, True)
    if not parsed:
        return
    slots = [e["pwd_id"] for e in parsed["entries"]]
    check("all three slots, in order", slots, [0, 3, 7])
    check("user_type 2 password", parsed["entries"][1]["password"], "1234")
    check("trailing entry still aligned", parsed["entries"][2]["password"], "5678")


def test_no_passwords_sentinel() -> None:
    """The NO_PASSWOED frame is a valid empty answer, not a parse failure."""
    print("no-passwords sentinel")
    parsed = parse_pwd_list_ack("a1b2c3d40a000c11019a", MC, UUID)
    check("recognised", parsed is not None, True)
    check("no entries", parsed["entries"] if parsed else None, [])
    check("host password is None", host_password_from([]), None)


def test_rejection_is_not_parsed_as_data() -> None:
    """A lock rejection must not be mistaken for a credential list."""
    print("rejection handling")
    check("FF rejection returns None",
          parse_pwd_list_ack("A1B2C3D40A000C93FF98", MC, UUID), None)


def test_operator_resolution() -> None:
    """Resolving who triggered an access event from the credential slot.

    Keypad and fingerprint events carry an empty ``na``, so the only identifying
    field is ``pid``.  Slot numbers are namespaced per credential type, so the
    same slot can map to two users and must not be guessed.
    """
    print("operator resolution")
    resolve = LocklyCoordinator._resolve_operator

    # Garage side door: one fingerprint at slot 7, one passcode at slot 1.
    lock = {"usrarr": [
        {"dutype": "F", "pid": 7, "fn": "Pat", "ln": ""},
        {"dutype": "P", "pid": 1, "fn": "Holly", "ln": "Forck"},
    ]}
    check("fingerprint slot resolves", resolve(lock, {"na": "", "pid": 7})[0], "Pat")
    check("passcode slot resolves", resolve(lock, {"na": "", "pid": 1})[0], "Holly Forck")
    check("an explicit na wins", resolve(lock, {"na": "Someone", "pid": 7})[0], "Someone")
    check("unknown slot is unresolved", resolve(lock, {"na": "", "pid": 99})[0], None)

    # Front Door: slot 1 exists as both a fingerprint and a passcode.
    ambiguous = {"usrarr": [
        {"dutype": "F", "pid": 1, "fn": "Pat", "ln": ""},
        {"dutype": "P", "pid": 1, "fn": "Holly", "ln": "Forck"},
    ]}
    name, candidates = resolve(ambiguous, {"na": "", "pid": 1})
    check("ambiguous slot is not guessed", name, None)
    check("ambiguous candidates reported", candidates, ["Holly Forck", "Pat"])


def main() -> int:
    for test in (
        test_unlock_plaintext,
        test_lock_differs_only_in_action,
        test_nonce_omitted_when_absent,
        test_status_frame_unchanged,
        test_ack_parse_real_capture,
        test_capabilities,
        test_query_pwd_frame,
        test_pwd_list_parsing,
        test_pwd_list_ignores_padding,
        test_user_type_2_has_no_schedule,
        test_no_passwords_sentinel,
        test_rejection_is_not_parsed_as_data,
        test_operator_resolution,
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
