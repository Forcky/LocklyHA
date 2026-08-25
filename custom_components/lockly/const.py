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

SERVICE_LIST_GUESTS  = "list_guests"
SERVICE_ADD_GUEST    = "add_guest"
SERVICE_DELETE_GUEST = "delete_guest"

BATTERY_MIN_V = 4.5
BATTERY_MAX_V = 6.0
