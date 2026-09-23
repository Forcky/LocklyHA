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

from custom_components.lockly.mqtt import LocklyMQTTManager, _truncate

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

    # The debug log is how every protocol question on this repo has been
    # answered, so a payload that fits must arrive whole.
    print("debug log truncation")
    short = json.dumps({"header": {"name": "deviceStateCallback"}, "payload": {"items": []}})
    check("a callback-sized payload is untouched", _truncate(short.encode()), short)
    long_payload = ("x" * 2500).encode()
    out = _truncate(long_payload)
    check("an oversized payload is cut at the limit", out.startswith("x" * 2000), True)
    check("and says how much it dropped", out.endswith("[500 more characters]"), True)

    print()
    print(f"{len(fails)} failure(s): {fails}" if fails else "all exchange checks passed")
    return 1 if fails else 0

sys.exit(asyncio.run(main()))
