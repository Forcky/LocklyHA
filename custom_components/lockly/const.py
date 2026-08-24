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

# How far back to seed the access-log cursor on first sync.  getlkhist takes a
# timestamp cursor and returns events oldest-first, so starting from 0 walks the
# lock's entire history a page at a time — on a lock with years of records that
# means "last access" reports something from years ago and never catches up.
HISTORY_LOOKBACK_DAYS = 7
SENDDATA_TIMEOUT = 30

SERVICE_LIST_GUESTS  = "list_guests"
SERVICE_ADD_GUEST    = "add_guest"
SERVICE_DELETE_GUEST = "delete_guest"

BATTERY_MIN_V = 4.5
BATTERY_MAX_V = 6.0
