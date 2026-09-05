"""Exercise the MQTT request/response plumbing without a broker.

The parts most likely to be subtly wrong are threaded: replies arrive on the
paho thread, every observed reply arrived twice, and a second delivery for an
already-resolved future would raise InvalidStateError.
"""
import asyncio, base64, json, sys, threading
sys.path.insert(0, "/config/lockly_test")  # set by the deploy step; see AGENTS.md

from custom_components.lockly.mqtt import LocklyMQTTManager

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

    print()
    print(f"{len(fails)} failure(s): {fails}" if fails else "all exchange checks passed")
    return 1 if fails else 0

sys.exit(asyncio.run(main()))
