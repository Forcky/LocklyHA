DOMAIN = "lockly"

API_BASE = "https://apiserv03c.lockly.com/pgsmtlkv2/api/"
API_USER_AGENT = "DoorLocker/329 (Pixel 8 Pro; Android 16)"

COMMON_BODY = {
    "appType": "LOCKLY",
    "ctry": "",
    "dvid": "",
    "locale": "EN",
    "os": "android",
    "rid1": "",
    "rid2": "",
    "tk": "",
    "ver": "329",
    "versionName": "3.2.9",
}

CONF_EMAIL = "email"
CONF_PASSWORD = "password"

SCAN_INTERVAL_SECONDS = 30
HISTORY_INTERVAL_SECONDS = 300  # 5 minutes — access log poll

# Login token renewal. Lockly's tokens last exactly 24 hours (exp - iat = 86400
# in every one seen), and nothing else here asks for a new one, so without this
# the token handed to the broker at startup is the one it is still offered a
# week later. The broker only checks it when a connection is made, which is why
# that goes unnoticed until the first reconnect — and then that reconnect is
# refused with rc=5. Renew this long before the token's own expiry...
TOKEN_RENEW_MARGIN_SECONDS = 3600
# ...but never sooner than this, so a token that arrives already close to
# expiry (or a clock that disagrees with Lockly's) cannot become a login loop.
# Also the wait before trying again after a renewal fails.
TOKEN_RENEW_MIN_SECONDS = 1800
# ...and never later than this, in case a token ever claims a longer life.
TOKEN_RENEW_MAX_SECONDS = 23 * 3600
# When the token's expiry cannot be read at all.
TOKEN_RENEW_FALLBACK_SECONDS = 12 * 3600

# First access-log fetch after setup. Short enough that Last Access populates
# promptly, long enough to stay clear of the startup burst.

# How far back to seed the access-log cursor on first sync.  getlkhist takes a
# timestamp cursor and returns events oldest-first, so starting from 0 walks the
# lock's entire history a page at a time — on a lock with years of records that
# means "last access" reports something from years ago and never catches up.
HISTORY_LOOKBACK_DAYS = 7

# First access-log fetch after setup.  async_track_time_interval only fires
# after a full interval, and HA can take minutes to reach this integration, so
# without this Last Access stays blank for roughly ten minutes after a restart.
HISTORY_INITIAL_DELAY_SECONDS = 30
SENDDATA_TIMEOUT = 30

# Attempts at the one-off live status query used to seed state when the hub's
# cachedstatus endpoint is unavailable.  A single attempt is not enough: a
# transient NACK or hub relay timeout cost the lock its state for the whole
# session.  The cap is what keeps retries from becoming a poll loop, since
# every attempt wakes the lock and some models beep when woken.
LIVE_INIT_MAX_ATTEMPTS = 3

# After those attempts are exhausted, one quiet probe on this interval, so a
# hub that comes back is noticed without needing an HA restart.  A single
# attempt rather than the startup burst, because this repeats for as long as the
# failure lasts and every attempt wakes the lock.  Long enough that a lock stuck
# unreachable for days is not woken often; short enough that recovery is picked
# up while someone is still standing at the door wondering why.
LIVE_INIT_REARM_SECONDS = 1800

# Pause before re-sending a command the cloud or hub timed out on. Long enough
# for a momentary relay failure to clear, short enough that a person waiting at
# a door does not give up on it.
SENDDATA_RETRY_DELAY_SECONDS = 3

# Hubs whose id starts with this are Matter hubs, and the only ones present on
# the MQTT device channel. BluetoothBean.isMatterHub() is exactly this prefix
# test, and it gates the app's own hub-signal screen. Older Secure LINK hubs
# (PGH200, PGH220) use the senddata REST relay instead.
MATTER_HUB_PREFIX = "PGH260"

SERVICE_LIST_GUESTS  = "list_guests"
SERVICE_ADD_GUEST    = "add_guest"
SERVICE_DELETE_GUEST = "delete_guest"
SERVICE_ENABLE_NATIVE_AUTO_LOCK = "enable_native_auto_lock"
SERVICE_DISABLE_NATIVE_AUTO_LOCK = "disable_native_auto_lock"

BATTERY_MIN_V = 4.5
BATTERY_MAX_V = 6.0
