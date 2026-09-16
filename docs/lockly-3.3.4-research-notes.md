# Lockly Android 3\.3\.4 Research Notes

These notes record the Android\-app analysis and hardware validation behind the
WiFi\-native `0x52` command support added in LocklyHA 0\.7\.4\. They complement the
canonical protocol description in [`api.md`](api.md) rather than replacing it\.

The work was performed for interoperability with two personally owned Lockly
Visage `PGK728WRHK` locks\. No lock identifiers, account identifiers, master
codes, host credentials, raw command frames, or captured traffic are included\.

## Scope and evidence

- Android app examined: Lockly 3\.3\.4\.
- Primary tools: JADX for Java\-level tracing and apktool/smali for targeted
  instrumentation preparation\.
- Relevant model path: `PGK728WRHK`, reported by the lock as type 105 and using
  the `isSupport82Cmd()` / `0x52` branch\.
- Hardware validation: two `PGK728WRHK` locks on firmware 1\.14\.31 and 3\.00\.24\.
- Result: lock and unlock both succeeded over MQTT on both firmware versions;
  Lockly’s `deviceStateCallback` confirmed the resulting state changes\.

The command construction findings below came from static analysis of the app,
not from a decrypted live capture\. Successful operation on both locks provides
the hardware validation for the resulting frame\.

## `NewUnlockCmd` findings

Tracing `NewUnlockCmd.getData()` in app version 3\.3\.4 showed that the host/network
form of the `0x52` command differs from the older `0x22` form in three important
ways\.

### Access\-user field is two\-byte little\-endian

For `PGK728WRHK`, `isSupportAccessUser()` is true\. The `0x52` branch therefore
uses `BluetoothBean.getUserId()` and encodes it through `getCmdLenString()`, which
produces a two\-byte little\-endian value\.

For the lock owner, the user ID is zero, so the field is:

```text
0000
```

This is two bytes, not a one\-byte slot value\. Sending only `00` makes the frame
one byte short and shifts the action, network flag, and trailing timestamp out of
position\.

### Trailing field is epoch milliseconds

For this model, the timestamp\-capable branch calls the equivalent of:

```java
DataUtils.o(System.currentTimeMillis())
```

The value is the phone’s Unix epoch time in milliseconds encoded as an
eight\-byte little\-endian integer &#40;16 hexadecimal characters&#41;\. It is not the
nonce obtained from the preceding status response, and it is not the six\-byte
packed local\-time format used by older commands\.

### Outer encryption type is `0x0B`

The host branch assigns encryption type 11\. The app’s frame wrapper stores that
value in the low nibble of the outer type byte:

```text
type_byte = (zero_padding_length << 4) | 0x0B
```

Using the older low nibble `0x05` does not reproduce the app’s `0x52` host path\.

## Corrected host/network layout

At the field level, the app’s type\-105 host/network command is:

```text
52 | mc_len | encrypted_mc | unlock_type | expanded_host_credential
   | LE16(owner_user_id=0) | action | network_flag=0 | LE64(epoch_ms)
```

The payload uses the existing per\-lock AES key derivation\. It is AES\-ECB
encrypted after zero padding and then wrapped with encryption type `0x0B`\.

All three corrections must be applied together\. Testing them independently can
be misleading because the one\-byte user\-ID length error changes how every later
field is parsed\.

## MQTT and cloud behavior observed

The two locks are WiFi\-native and have no Secure Link hub\. The hub\-oriented
`senddata` path therefore returns `cod=930`\. The locks are nevertheless reachable
over Lockly’s MQTT transport\.

`QueryPwd147` &#40;`0x93`&#41; returned `0xFA` on these locks, so the integration used the
host credential from the cloud device record\. The earlier `0xFF` response did
not prove that credential was wrong; the corrected `0x52` frame accepted the
same credential and operated both locks\.

## Local prototype: WiFi\-native MQTT lock\-state callbacks

The live lock\-state behavior was observed with a **locally modified v0\.7\.4**
**installation**, not with stock v0\.7\.4 or v0\.7\.5\. A comparison of the installed
files with the v0\.7\.4 tag confirmed that the relevant lock\-state changes were
limited to `mqtt.py`\.

Stock `_process_device_state()` looked for `items` at the JSON root and handled
legacy uppercase state keys such as `LOCKED_STATUS`\. Captured Visage callbacks
instead wrapped the item list under `payload.items` and used the lowercase
named key `lock`, with a value of `locked` or `unlocked`\.

The local `mqtt.py` prototype therefore:

- reads `(data.get("payload") or {}).get("items")`;
- retains the existing legacy uppercase\-key handling;
- maps lowercase `lock` values to the coordinator’s `is_locked` field; and
- uses the existing `async_set_updated_data()` path to publish the update to
  Home Assistant\.

With that prototype installed, a manual unlock performed outside Home
Assistant updated the lock entity through `deviceStateCallback`; later lock
events did the same\. Lockly callbacks also confirmed state changes after
commands initiated from Home Assistant\.

This is an open implementation lead for upstream review, not a description of
current stock LocklyHA behavior\. The separate local battery experiment is
intentionally excluded from this documentation change and should be proposed
separately together with its code\.

## Open investigation: magnetic/door sensor

The magnetic/door\-sensor issue is **not fixed**\. Work is continuing to determine
how the WiFi\-native Visage reports door state and sensor presence across the
decrypted status response and MQTT `deviceStateCallback` messages\.

The lock entity updating correctly after a manual unlock or later lock event
must not be treated as proof that the door entity is correct: bolt state and
magnetic door state are distinct signals\. In particular, an open magnetic
circuit may be ambiguous between an open door and a lock with no sensor fitted,
and the MQTT representation may not use the same bit layout as the decrypted
status byte\.

Maintainer review identified a concrete status\-byte lead for the next physical
test: the Android app appears to select bit 0 when `rfId == FFFFFFFF` and bit 2
otherwise, while bits 1 and 3 appear related to sensor presence\. This mapping
has not yet been validated on the two test locks\. The next step is to record the
decrypted status byte with the physical door shut and open, while keeping the
bolt state controlled, and compare the resulting bit changes\. MQTT named keys
must be evaluated separately because they are not necessarily the same
representation as the decrypted status byte\.

Any insight from Patrick/Forcky on the Visage magnet field, status\-bit mapping,
or expected callback semantics would be welcome\. Until that behavior is
validated against repeated physical open/close tests, the magnetic\-sensor work
should be described as ongoing rather than supported\.

## Instrumentation work that was prepared

Before the static analysis produced a working frame, an instrumented Lockly
3\.3\.4 build was prepared for a possible live capture:

1. The APK was unpacked and a Frida Gadget library was added for the test
   device’s architecture\.
2. A targeted smali change loaded the gadget from the application class’s
   static initializer\.
3. The APK was rebuilt, signed, signature\-verified, and installed on a dedicated
   Android test device\.

No live capture was required after LocklyHA 0\.7\.4 succeeded on both locks\. The
modified APK, signing material, unredacted traces, and runtime data are
intentionally not included in this public documentation\. They should only be
shared privately if a future interoperability problem genuinely requires them\.

## Reproducibility notes

- Obfuscated method names can change between app versions\. Follow data flow and
  behavior rather than relying only on a particular one\-letter method name\.
- Confirm both the model capability predicates and the selected command branch;
  finding a helper method does not prove a model calls it\.
- Preserve field widths while translating Java string assembly into bytes\.
  Automatic hex padding can hide a one\-byte versus two\-byte mismatch\.
- Treat `0xFF` as the lock’s interpretation of the complete frame, not as proof
  that one named credential source is wrong\.
- Keep static\-analysis conclusions distinct from capture evidence and hardware
  validation\.

## Attribution

Research and hardware testing: Brian Salyer &#40;`Dei381rcr`&#41;, with independent
cross\-checking and implementation by Patrick/Forcky\. The investigation and
release validation are recorded in [Issue \#3](https://github.com/Forcky/LocklyHA/issues/3)\.
