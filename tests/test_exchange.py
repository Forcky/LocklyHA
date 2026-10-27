"""Exercise the MQTT request/response plumbing without a broker.

The parts most likely to be subtly wrong are threaded: replies arrive on the
paho thread, every observed reply arrived twice, and a second delivery for an
already-resolved future would raise InvalidStateError.
"""
import asyncio
import base64
import json
import sys
import threading
import time
sys.path.insert(0, "/config/lockly_test")  # set by the deploy step; see AGENTS.md

from custom_components.lockly.mqtt import LocklyMQTTManager, _mqtt_username, _truncate

ACK = "A1B2C3D429000A1E95A9B99DCBC5945E531B5EB4A643BA93BE5696D79B9791D9392AC7509E8BB800A2"
fails = []

def check(label, actual, expected):
    if actual == expected:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}: expected {expected!r}, got {actual!r}")
        fails.append(label)

class FakeInfo:
    rc = 0

class FakeClient:
    def __init__(self): self.published = []
    def publish(self, topic, body, qos=0):
        self.published.append((topic, body))
        return FakeInfo()

class FakeHass:
    def __init__(self, loop): self.loop = loop
    async def async_add_executor_job(self, fn, *a): return fn(*a)
    def async_create_task(self, coro): return self.loop.create_task(coro)

class FakeCoordinator:
    """Enough of the coordinator for _process_device_state to write into."""
    def __init__(self, data): self.data, self.writes = data, 0
    def async_set_updated_data(self, data):
        self.data, self.writes = data, self.writes + 1

def state_msg(where, device_id, states):
    """A deviceStateCallback with the item list at the root or under payload."""
    items = [{"deviceId": device_id,
              "states": [{"statusKey": k, "statusValue": v} for k, v in states.items()]}]
    msg = {"header": {"name": "deviceStateCallback"}}
    if where == "payload":
        msg["payload"] = {"items": items}
    else:
        msg["items"] = items
    return msg

def reply_for(body_json, *, content=ACK, code=0, name="lockCommandResponse"):
    rid = json.loads(body_json)["header"]["requestId"]
    payload = {"code": code, "errorMessage": None,
               "commandContent": base64.b64encode(bytes.fromhex(content)).decode()}
    if name == "exception":
        payload = {"code": code, "message": "device is offline"}
    return rid, payload

async def main():
    loop = asyncio.get_running_loop()
    hass = FakeHass(loop)
    m = LocklyMQTTManager(hass, object())
    cli = FakeClient()
    m._client, m._connected = cli, True

    print("exchange: normal reply")
    task = asyncio.create_task(m.async_exchange_frame("dev1", ACK, timeout=5))
    await asyncio.sleep(0.05)
    rid, payload = reply_for(cli.published[-1][1])
    # Deliver from another thread, exactly as paho does.
    threading.Thread(target=lambda: m._resolve(rid, payload)).start()
    got = await task
    check("returns the ACK hex", got, ACK)
    check("published to 'server'", cli.published[-1][0], "server")

    print("exchange: duplicate reply is ignored")
    task = asyncio.create_task(m.async_exchange_frame("dev1", ACK, timeout=5))
    await asyncio.sleep(0.05)
    rid, payload = reply_for(cli.published[-1][1])
    for _ in range(3):                      # the broker sends each reply twice
        threading.Thread(target=lambda: m._resolve(rid, payload)).start()
    got = await task
    await asyncio.sleep(0.1)                # let the late duplicates land
    check("still returns the ACK", got, ACK)
    check("no pending futures leaked", len(m._pending), 0)

    print("exchange: server exception")
    task = asyncio.create_task(m.async_exchange_frame("dev1", ACK, timeout=5))
    await asyncio.sleep(0.05)
    rid = json.loads(cli.published[-1][1])["header"]["requestId"]
    m._resolve(rid, {"code": 3005, "errorMessage": "device is offline"})
    check("returns None on a server error", await task, None)

    print("exchange: timeout")
    got = await m.async_exchange_frame("dev1", ACK, timeout=0.3)
    check("returns None, does not hang", got, None)
    check("pending cleaned up after timeout", len(m._pending), 0)

    print("exchange: not connected")
    m._connected = False
    check("returns None when disconnected",
          await m.async_exchange_frame("dev1", ACK, timeout=1), None)

    # ── deviceStateCallback ──────────────────────────────────────────────────
    # Shapes from a Visage capture on issue #5. The item list is under
    # "payload", and the lock key is lowercase with a word value — neither of
    # which the old reader matched, so every callback was silently dropped.
    print("device state: payload.items with a lowercase word value")
    coord = FakeCoordinator({"dev1": {"is_locked": True}})
    m._coordinator = coord
    await m._process_device_state(state_msg("payload", "dev1", {"lock": "unlocked"}))
    check("unlocked was applied", coord.data["dev1"]["is_locked"], False)
    check("published once", coord.writes, 1)

    print("device state: legacy root items with LOCKED_STATUS")
    coord = FakeCoordinator({"dev1": {"is_locked": False}})
    m._coordinator = coord
    await m._process_device_state(state_msg("root", "dev1", {"LOCKED_STATUS": "1"}))
    check("legacy shape still works", coord.data["dev1"]["is_locked"], True)

    print("device state: magnet, and the key's case does not matter")
    coord = FakeCoordinator({"dev1": {}})
    m._coordinator = coord
    await m._process_device_state(
        state_msg("payload", "dev1", {"MAGNET": "1", "Lock": "locked"})
    )
    check("door read as open", coord.data["dev1"]["door_sensor_open"], True)
    check("lock read whatever the case", coord.data["dev1"]["is_locked"], True)

    print("device state: an unknown value changes nothing")
    coord = FakeCoordinator({"dev1": {"is_locked": True}})
    m._coordinator = coord
    await m._process_device_state(state_msg("payload", "dev1", {"lock": "ajar"}))
    check("state left alone", coord.data["dev1"]["is_locked"], True)
    check("nothing published", coord.writes, 0)

    print("device state: a lock we do not know is ignored")
    coord = FakeCoordinator({"dev1": {"is_locked": True}})
    m._coordinator = coord
    await m._process_device_state(state_msg("payload", "other", {"lock": "unlocked"}))
    check("no write for an unknown device", coord.writes, 0)

    print("device state: deviceId case is normalised")
    coord = FakeCoordinator({"2d0023": {"is_locked": True}})
    m._coordinator = coord
    await m._process_device_state(state_msg("payload", "2D0023", {"lock": "unlocked"}))
    check("uppercase id matches our lowercase key", coord.data["2d0023"]["is_locked"], False)

    # The magnet value a Visage actually sends is "opened", not "open". This set
    # held only "open", so a door closing was recorded and a door opening was
    # dropped — the sensor could reach closed and never leave it. Captured on #10.
    print("device state: magnet word forms")
    for value, expected in (("opened", True), ("closed", False), ("OPENED", True)):
        coord = FakeCoordinator({"dev1": {}})
        m._coordinator = coord
        await m._process_device_state(state_msg("payload", "dev1", {"magnet": value}))
        check(f"magnet={value!r} reads door_open={expected}",
              coord.data["dev1"].get("door_sensor_open"), expected)

    # Only a status query used to prove a door sensor, so after a restart the
    # Door entity stayed unavailable until one read the door shut — hours on a
    # lock left alone overnight (#10) — though closed callbacks kept arriving.
    print("device state: a closed callback proves the door sensor")

    class ProvingCoordinator(FakeCoordinator):
        def __init__(self, data):
            super().__init__(data)
            self._door_sensor_proven = set()

    coord = ProvingCoordinator({"dev1": {}})
    m._coordinator = coord
    await m._process_device_state(state_msg("payload", "dev1", {"magnet": "opened"}))
    check("an open door proves nothing", coord._door_sensor_proven, set())
    check("and leaves the sensor unproven",
          coord.data["dev1"].get("wired_door_sensor_connected"), None)
    await m._process_device_state(state_msg("payload", "dev1", {"magnet": "closed"}))
    check("a closed door proves the sensor", coord._door_sensor_proven, {"dev1"})
    check("and makes the Door entity available",
          coord.data["dev1"].get("wired_door_sensor_connected"), True)
    await m._process_device_state(state_msg("payload", "dev1", {"magnet": "opened"}))
    check("once proven, an open door stays a reading, not a missing sensor",
          (coord.data["dev1"]["door_sensor_open"],
           coord.data["dev1"]["wired_door_sensor_connected"]), (True, True))

    print("device state: battery percentage")
    coord = FakeCoordinator({"dev1": {}})
    m._coordinator = coord
    await m._process_device_state(state_msg("payload", "dev1", {"battery": "100"}))
    check("a percentage is published", coord.data["dev1"]["battery_percent"], 100)

    coord = FakeCoordinator({"dev1": {"battery_percent": 80}})
    m._coordinator = coord
    await m._process_device_state(state_msg("payload", "dev1", {"battery": "255"}))
    check("an impossible percentage is refused, not clamped",
          coord.data["dev1"]["battery_percent"], 80)
    check("and nothing is published", coord.writes, 0)

    coord = FakeCoordinator({"dev1": {"battery_percent": 80}})
    m._coordinator = coord
    await m._process_device_state(state_msg("payload", "dev1", {"battery": "unknown"}))
    check("so is a non-numeric one", coord.data["dev1"]["battery_percent"], 80)

    print("device state: one callback carrying everything")
    coord = FakeCoordinator({"dev1": {}})
    m._coordinator = coord
    await m._process_device_state(state_msg(
        "payload", "dev1", {"lock": "unlocked", "magnet": "opened", "battery": "95"}
    ))
    check("lock applied", coord.data["dev1"]["is_locked"], False)
    check("door applied", coord.data["dev1"]["door_sensor_open"], True)
    check("battery applied", coord.data["dev1"]["battery_percent"], 95)
    check("published once for the batch", coord.writes, 1)

    # The debug log is how every protocol question on this repo has been
    # answered, so a payload that fits must arrive whole.
    print("debug log truncation")
    short = json.dumps({"header": {"name": "deviceStateCallback"}, "payload": {"items": []}})
    check("a callback-sized payload is untouched", _truncate(short.encode()), short)
    long_payload = ("x" * 2500).encode()
    out = _truncate(long_payload)
    check("an oversized payload is cut at the limit", out.startswith("x" * 2000), True)
    check("and says how much it dropped", out.endswith("[500 more characters]"), True)

    # The hardcoded broker is right for the account this was built against, and
    # an rc=5 there used to end push for good. Another account's API reports a
    # different Lockly broker (#14), so that one is kept as a second try.
    print("broker candidates")

    class FakeCoord:
        def __init__(self, host=None, port=None):
            self.mqtt_host, self.mqtt_port = host, port
            self.data = {}

    m._coordinator = FakeCoord()
    check("no API address — one candidate", len(m._brokers()), 1)

    m._coordinator = FakeCoord("mqtt-clb-1143679798.us-west-2.elb.amazonaws.com", 8883)
    cands = m._brokers()
    check("API address is a second candidate", len(cands), 2)
    check("the hardcoded one is still tried first", cands[0][0].startswith("mqttuswest02"), True)
    check("then the reported one", cands[1], ("mqtt-clb-1143679798.us-west-2.elb.amazonaws.com", 8883))

    m._coordinator = FakeCoord("mqtt-clb-1143679798.us-west-2.elb.amazonaws.com", None)
    check("a missing port falls back to 8883", m._brokers()[1][1], 8883)

    m._coordinator = FakeCoord(cands[0][0], 8883)
    check("the same address is not tried twice", len(m._brokers()), 1)

    # The app lowercases the whole username before connecting — Connection
    # .createOptions, name.toLowerCase(Locale.ROOT). This sent the address as
    # typed, so a capitalised email logged in over REST and was refused by the
    # broker with rc=5, which reads as an account problem (#14).
    print("broker username")
    check("a typed-in capital is lowered",
          _mqtt_username("Name@Example.COM"), "name@example.com")
    check("an already-lower address is untouched",
          _mqtt_username("name@example.com"), "name@example.com")
    check("the client id form is lowered whole",
          _mqtt_username("Name@Example.com", "01ABC"), "01abc_name@example.com")
    check("no client id means no prefix",
          _mqtt_username("a@b.com", None), "a@b.com")

    # ── refusal recovery ─────────────────────────────────────────────────────
    # A refusal from every broker address used to end push until Home
    # Assistant restarted. Every rc=5 in a month of logs on the development
    # account followed the token, and a fresh login cleared each one, so the
    # client now comes back with a new login on a slow schedule.
    import custom_components.lockly.mqtt as mqtt_mod

    scheduled = []

    def fake_call_later(_hass, delay, job):
        scheduled.append((delay, job))
        return lambda: scheduled.append(("cancelled", delay))

    mqtt_mod.async_call_later = fake_call_later

    class StopClient:
        def __init__(self):
            self.stopped = self.disconnected = 0
            self.subscribed, self.creds = [], None
        def loop_stop(self): self.stopped += 1
        def disconnect(self): self.disconnected += 1
        def subscribe(self, topic, qos=0): self.subscribed.append(topic)
        def username_pw_set(self, user, pwd): self.creds = (user, pwd)

    class RecoveryCoord:
        def __init__(self, renew_ok=True, host=None):
            self.mqtt_host, self.mqtt_port, self.mqtt_client_id = host, None, None
            self.email, self.jwt, self.data = "Me@Example.com", "token-1", {}
            self.renew_ok, self.renewals = renew_ok, 0
        async def async_renew_login(self):
            self.renewals += 1
            if self.renew_ok:
                self.jwt = f"token-{self.renewals + 1}"
            return self.renew_ok

    def manager_for(coord):
        """A manager with a fake client, recording each session it starts."""
        mgr = LocklyMQTTManager(hass, coord)
        mgr._client = StopClient()
        starts = []
        async def fake_start():
            starts.append(mgr._broker_index)
        mgr.async_start = fake_start
        return mgr, starts

    print("refusal recovery: every address refused")
    coord = RecoveryCoord()
    mgr, starts = manager_for(coord)
    client = mgr._client
    scheduled.clear()
    mgr._handle_connect(client, 5, "cid")
    await asyncio.sleep(0)
    check("paho's loop is stopped", client.stopped, 1)
    check("a fresh-login retry is scheduled in 30 s", [d for d, _ in scheduled], [30])
    check("not reported as connected", mgr.connected, False)

    mgr._broker_index = 1            # as if the reported address was the last tried
    await scheduled[-1][1](None)
    check("the retry logs in afresh", coord.renewals, 1)
    check("and starts again from the first address", starts, [0])

    print("refusal recovery: schedule")
    mgr, _ = manager_for(RecoveryCoord())
    delays = [mgr._next_recovery_delay() for _ in range(9)]
    check("delays grow", delays[:7], [30, 300, 1800, 3600, 7200, 14400, 21600])
    check("then hold at six hours", delays[7:], [21600, 21600])
    accepted = StopClient()
    mgr._handle_connect(accepted, 0, "cid")
    check("a connection is reported", mgr.connected, True)
    check("and subscribes to its own topic", accepted.subscribed, ["client/cid"])
    check("and resets the schedule", mgr._next_recovery_delay(), 30)

    print("refusal recovery: the login itself fails")
    coord = RecoveryCoord(renew_ok=False)
    mgr, starts = manager_for(coord)
    scheduled.clear()
    mgr._handle_connect(mgr._client, 5, "cid")
    await asyncio.sleep(0)
    await scheduled[-1][1](None)
    check("no connection is attempted with the refused token", starts, [])
    check("the next retry is further out", [d for d, _ in scheduled], [30, 300])

    print("refusal recovery: a transient refusal")
    mgr, _ = manager_for(RecoveryCoord())
    scheduled.clear()
    mgr._handle_connect(mgr._client, 3, "cid")
    await asyncio.sleep(0)
    check("leaves paho to retry by itself", (mgr._client.stopped, scheduled), (0, []))

    print("refusal recovery: a second address comes first")
    coord = RecoveryCoord(host="mqtt-clb-1143679798.us-west-2.elb.amazonaws.com")
    mgr, starts = manager_for(coord)
    scheduled.clear()
    mgr._handle_connect(mgr._client, 5, "cid")
    await asyncio.sleep(0.05)
    check("the reported address is tried", (mgr._broker_index, starts), (1, [1]))
    check("before any fresh-login retry", scheduled, [])

    print("refusal recovery: shutdown")
    mgr, starts = manager_for(RecoveryCoord())
    scheduled.clear()
    mgr._handle_connect(mgr._client, 5, "cid")
    await asyncio.sleep(0)
    retry = scheduled[0][1]
    await mgr.async_shutdown()
    check("cancels the pending retry", scheduled[-1][0], "cancelled")
    await retry(None)
    check("and a retry already under way does not reconnect", starts, [])
    await LocklyMQTTManager.async_start(mgr)
    check("nor can anything else start a session", mgr._client, None)

    # paho offers the credentials it was given on every reconnect, so a token
    # renewed by the coordinator has to reach the live client.
    print("renewed token reaches the live client")
    coord = RecoveryCoord()
    mgr, _ = manager_for(coord)
    coord.jwt = "renewed"
    mgr.async_update_credentials()
    check("username lowered, new token as password",
          mgr._client.creds, ("me@example.com", "renewed"))
    mgr._client = None
    mgr.async_update_credentials()   # no client: nothing to do, must not raise

    # ── login token renewal ──────────────────────────────────────────────────
    # Lockly's tokens last 24 hours, and nothing renewed them: the one given at
    # startup was offered to the broker for as long as Home Assistant ran.
    print("login token renewal timing")
    from custom_components.lockly.api import jwt_expiry, token_renewal_delay

    def make_jwt(claims):
        def enc(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        return f"{enc({'alg': 'HS256'})}.{enc(claims)}.signature"

    now = 1_800_000_000
    day = make_jwt({"iat": now, "exp": now + 86400})
    check("exp is read", jwt_expiry(day), now + 86400)
    check("renewed an hour before a 24 h token expires", token_renewal_delay(day, now), 82800)
    check("never sooner than half an hour",
          token_renewal_delay(make_jwt({"exp": now + 600}), now), 1800)
    check("an expired token gets the same floor",
          token_renewal_delay(make_jwt({"exp": now - 5}), now), 1800)
    check("never later than 23 h",
          token_renewal_delay(make_jwt({"exp": now + 30 * 86400}), now), 23 * 3600)
    check("an unreadable token is renewed after 12 h",
          token_renewal_delay("not-a-jwt", now), 12 * 3600)
    check("as is a missing one", token_renewal_delay(None, now), 12 * 3600)

    # The coordinator side, driven through its own methods on a stand-in.
    print("login token renewal in the coordinator")
    import custom_components.lockly as lockly_mod

    Coord = lockly_mod.LocklyCoordinator
    # Twenty hours left, so the expected wait (19 h) is neither cap nor floor.
    fresh = make_jwt({"exp": int(time.time()) + 20 * 3600})
    renewals_scheduled = []
    lockly_mod.async_call_later = (
        lambda _h, delay, job: renewals_scheduled.append(delay) or (lambda: None)
    )

    class StandIn:
        """Just the attributes _login and the renewal paths touch."""
        def __init__(self):
            self.hass, self.email, self.password = None, "a@b.com", "pw"
            self.jwt, self.locks, self.des3_key = "old", [{"ID": "x"}], b"k" * 24
            self.mqtt_client_id = self.mqtt_host = self.mqtt_port = None
            self._session, self._token_renewal_cancel = object(), None
            self._live_init_attempts = {}
            self.config_entry = type("Entry", (), {"entry_id": "01ABC"})()
            self.credential_updates = 0
            self._mqtt_manager = self
        async def _ensure_session(self): pass
        def async_update_credentials(self): self.credential_updates += 1
        def _schedule_token_renewal(self, delay=None):
            Coord._schedule_token_renewal(self, delay)
        async def _login(self): await Coord._login(self)
        async def async_renew_login(self): return await Coord.async_renew_login(self)
        async def _async_renew_token(self, _now=None): await Coord._async_renew_token(self, _now)

    async def login_ok(_s, _e, _p): return fresh
    async def login_refused(_s, _e, _p): return None
    async def devices_ok(_s, _j, _e): return [{"ID": "x"}, {"ID": "y"}], b"n" * 24
    async def devices_none(_s, _j, _e): return [], None
    async def heartbeat(_s, _j, _k, _d): return None

    lockly_mod.api_get_heartbeat = heartbeat
    lockly_mod.api_login, lockly_mod.api_get_devices = login_ok, devices_ok
    c = StandIn()
    renewals_scheduled.clear()
    await Coord._async_renew_token(c)
    check("a renewal takes the new token", c.jwt, fresh)
    check("and the new device list", len(c.locks), 2)
    check("hands it to the MQTT client", c.credential_updates, 1)
    check("schedules the next an hour before the token expires",
          len(renewals_scheduled) == 1 and abs(renewals_scheduled[0] - 19 * 3600) < 5, True)
    check("and wakes no lock", c._live_init_attempts, {})

    lockly_mod.api_get_devices = devices_none
    c = StandIn()
    renewals_scheduled.clear()
    await Coord._async_renew_token(c)
    check("a renewal whose device list fails keeps the old token", c.jwt, "old")
    check("and the old locks", c.locks, [{"ID": "x"}])
    check("tells the MQTT client nothing", c.credential_updates, 0)
    check("and tries again in half an hour", renewals_scheduled, [1800])

    lockly_mod.api_login = login_refused
    c = StandIn()
    check("a refused login reports failure rather than raising", await Coord.async_renew_login(c), False)
    check("and keeps the old token", c.jwt, "old")

    # A poll that returns a status used to rebuild the lock's data from the
    # lock list and that status alone, erasing the battery percentage the lock
    # had pushed over MQTT (#10) and the last access event.
    print("a poll keeps what only other routes deliver")

    async def cached(_s, _j, _k, _e, _lock):
        return {"is_locked": True, "low_battery": False, "door_sensor_open": False}

    lockly_mod.api_cached_status = cached

    class PollStandIn:
        def __init__(self):
            self.jwt, self.des3_key, self.email = "t", b"k" * 24, "a@b.com"
            self.locks = [{"ID": "x", "na": "Back Door"}]
            self.data = {"x": {"ID": "x", "battery_percent": 96,
                               "last_access_event": {"tm": 1}, "wakeup_voltage": 65376,
                               "is_locked": False}}
            self._session, self._cache_supported = object(), True
            self._live_init_attempts, self._live_init_retry_at = {}, {}
            self._capabilities, self._door_sensor_proven, self._nonces = {}, set(), {}
        async def _ensure_session(self): pass
        def _learn_from_status(self, lock, status):
            Coord._learn_from_status(self, lock, status)

    out = await Coord._async_update_data(PollStandIn())
    check("the pushed battery percentage survives", out["x"].get("battery_percent"), 96)
    check("so does the last access event", out["x"].get("last_access_event"), {"tm": 1})
    check("the new reading is applied", out["x"].get("is_locked"), True)
    check("an old voltage is not carried over", "wakeup_voltage" in out["x"], False)

    print()
    print(f"{len(fails)} failure(s): {fails}" if fails else "all exchange checks passed")
    return 1 if fails else 0

sys.exit(asyncio.run(main()))
