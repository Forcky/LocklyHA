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

    print()
    print(f"{len(fails)} failure(s): {fails}" if fails else "all exchange checks passed")
    return 1 if fails else 0

sys.exit(asyncio.run(main()))
