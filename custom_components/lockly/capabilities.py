"""Per-model Lockly capability flags.

Lockly hardware does not share one BLE command format.  The app decides which
frame to build from a numeric lock type, via the ``isPGxxx()`` predicates on
``BluetoothBean``.  This module ports the subset of those predicates that
affect the frames this integration builds.

Where the lock type comes from
------------------------------
``BluetoothBean.getLockType()`` parses the bean's ``lockType`` string and
**falls back to 1** when it is absent.  The ``qrylknew`` cloud response does not
carry ``lockType`` — the lock reports it itself, as byte 18 of the decrypted
status ACK (``QueryLockStatusCmd`` reads ``data[36:38]``).  So the flow is:
query status once, learn the lock type, then build commands for it.  Until a
status response has been seen, ``DEFAULT_CAPABILITIES`` (lock type 1) applies,
which is the same fallback the app uses.

Model numbers below are from ``BluetoothBean.isPGxxx()`` in Lockly app 3.2.9.
"""
from __future__ import annotations

from dataclasses import dataclass

# ── Command codes ─────────────────────────────────────────────────────────────

CMD_QUERY_STATUS = "1E"     # MessageManage.CODE_NEW_QUERY_LOCK_STATUS
CMD_UNLOCK = "22"           # NewUnlockCmd, standard AES path
CMD_UNLOCK_82 = "52"        # NewUnlockCmd, isSupport82Cmd path
CMD_QUERY_PASSWORDS = "93"  # QueryPwd147Cmd — paginated credential list

# QueryPwdCmd.NO_PASSWOED: the sentinel frame meaning "this lock holds none".
_NO_PASSWORDS_ACK = "a1b2c3d40a000c11019a"

# ── Frame field values ────────────────────────────────────────────────────────

# str2 in NewUnlockCmd.getData — MessageManage lock/unlock type.
ACTION_UNLOCK = "01"
ACTION_LOCK = "02"

# getUnLockType(): "2" for a host/admin, "3" for long-term or staff users.
UNLOCK_TYPE_HOST = "2"
UNLOCK_TYPE_LONG_TERM = "3"

# str3 in NewUnlockCmd.getData.  getDataForHub passes "1"; getDataForBluetooth
# and getDataForNetwork pass "0".  Cloud senddata is always hub-relayed.
_STR3_HUB = "1"
_STR3_DIRECT = "0"

# ── Lock type sets, ported from BluetoothBean ────────────────────────────────

_LOCK_TYPE_FALLBACK = 1  # BluetoothBean.getLockType() default

# isPGI301() — excluded from the timestamp path even though it is an 0x52 lock.
_PGI301 = 121

# isSupport82Cmd(), unconditional members.
_SUPPORTS_82_CMD = frozenset({
    51,   # PGI302FC
    54,   # PGI303FC
    102,  # PGK7SWH
    103,  # PGK7SWHK
    104,  # PGK728WHK
    105,  # PGK728WRHK
    113,  # PGD899G
    117,  # PGK798HK
    121,  # PGI301
    124,  # PGD728FG25
    125,  # PGD728FNG25
    127,  # PGD628FG25
    128,  # PGK728WKL
    132,  # PGD7AWG25
    133,  # PGD7YWG25
})

# isSupport82Cmd() members gated on a firmware check we do not implement
# (DeviceVersionManager.m57412m / m57414o).  Treated as NOT supporting 0x52 so
# we fall back to the widely-working 0x22 frame rather than guessing.
_MAYBE_82_CMD = frozenset({
    67,  # PGI302W  — DeviceVersionManager.m57412m
    71,  # PGV528   — DeviceVersionManager.m57414o
})

# isVision()
_VISION = frozenset({
    35,   # PGD798
    54,   # PGI303FC
    69,   # PGD698L
    74,   # PGD698D
    78,   # PGD898
    79,   # PGD798C
    80,   # PGD798NV
    84,   # PGD899
    93,   # PGD798D
    94,   # PGD698LL
    95,   # PGD698DL
    96,   # PGD898D
    97,   # PGD898S
    100,  # PGD898X
    107,  # PGD897D
    112,  # PGD899X
    113,  # PGD899G
    115,  # PGD798UZ
    117,  # PGK798HK
})

# isSupport500GroupPassword(): PGD728FN21 always, PGD238T from lock fw 1.00.01.
_500_GROUP_PASSWORD = frozenset({129})       # PGD728FN21
_500_GROUP_PASSWORD_VERSIONED = frozenset({88})  # PGD238T

# Model string -> lock type, for the models this project has evidence for.
# Only used as a hint before the first status response arrives; the lock's own
# reported type always wins.
MODEL_LOCK_TYPES = {
    "PGD628F": 4,
    "PGD628FN": 21,
    "PGD628FG25": 127,
    "PGD728F": 2,
    "PGD728FN": 22,
    "PGD728FG25": 124,
    "PGD728FNG25": 125,
    "PGD728FN21": 129,
}


@dataclass(frozen=True)
class LockCapabilities:
    """Frame-shaping capabilities for one lock."""

    lock_type: int = _LOCK_TYPE_FALLBACK
    model: str = ""
    is_host: bool = True

    @property
    def supports_82_cmd(self) -> bool:
        """isSupport82Cmd(): lock uses the 0x52 command set."""
        return self.lock_type in _SUPPORTS_82_CMD

    @property
    def is_vision(self) -> bool:
        """isVision(): Lockly Vision family (camera doorbell locks)."""
        return self.lock_type in _VISION

    @property
    def supports_500_group_password(self) -> bool:
        """isSupport500GroupPassword(): extra "02" + wide slot id in the frame.

        The PGD238T half of this predicate is firmware-gated in the app; we
        report False for it so we build the frame we can verify.
        """
        return self.lock_type in _500_GROUP_PASSWORD

    @property
    def supports_timestamp(self) -> bool:
        """isSupportTimestamp(): nonce field carries a timestamp, not the stored value.

        ``(isHost() && isVision()) || (isSupport82Cmd() && !isPGI301())``
        """
        if self.is_host and self.is_vision:
            return True
        return self.supports_82_cmd and self.lock_type != _PGI301

    @property
    def cmd_code(self) -> str:
        """BLE command code for lock/unlock on this hardware."""
        return CMD_UNLOCK_82 if self.supports_82_cmd else CMD_UNLOCK

    @property
    def slot_id(self) -> int:
        """Credential slot in the frame — DataUtils.m86645J(pwdId), or getUserId() on 0x52.

        The app sets pwdId to 0 for host unlocks on locks that support access
        users, and 1 otherwise; 1 is the value verified against 0x22 hardware.
        """
        return 1

    @property
    def needs_firmware_check(self) -> bool:
        """True when a firmware-gated predicate makes the frame choice uncertain."""
        return self.lock_type in _MAYBE_82_CMD

    def __str__(self) -> str:
        parts = [f"type={self.lock_type}"]
        if self.model:
            parts.append(self.model)
        parts.append(f"cmd=0x{self.cmd_code}")
        if self.supports_82_cmd:
            parts.append("82cmd")
        if self.is_vision:
            parts.append("vision")
        if self.supports_500_group_password:
            parts.append("500group")
        if self.supports_timestamp:
            parts.append("timestamp")
        return " ".join(parts)


DEFAULT_CAPABILITIES = LockCapabilities()


def resolve_capabilities(lock: dict, lock_type: int | None = None) -> LockCapabilities:
    """Build capabilities for a lock.

    ``lock_type`` is the value the lock reported in its status ACK.  When it is
    None we fall back to the model-string hint, then to the app's default of 1.
    """
    model = str(lock.get("mod") or "")
    if lock_type is None:
        lock_type = MODEL_LOCK_TYPES.get(model.upper(), _LOCK_TYPE_FALLBACK)
    return LockCapabilities(
        lock_type=lock_type,
        model=model,
        is_host=str(lock.get("secondAdm") or "N").upper() != "Y",
    )
