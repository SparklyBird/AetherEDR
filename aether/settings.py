"""Django settings. Everything runs locally: SQLite in WAL mode, no external services."""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
# read-only resources; PyInstaller unpacks these to _MEIPASS
BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))


def _data_dir() -> Path:
    env = os.environ.get("AETHER_DATA_DIR")
    if env:
        p = Path(env)
    elif FROZEN:
        p = Path(sys.executable).resolve().parent / "data"
    else:
        p = BASE_DIR / "data"
    p.mkdir(parents=True, exist_ok=True)
    return p


DATA_DIR = _data_dir()


def _persisted_secret(name: str, env: str | None = None) -> str:
    """Random secret, saved in DATA_DIR (0600 where the OS allows it)."""
    if env and os.environ.get(env):
        return os.environ[env]
    path = DATA_DIR / name
    if path.exists():
        value = path.read_text().strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    path.write_text(value)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


SECRET_KEY = _persisted_secret("secret_key", "AETHER_SECRET_KEY")
API_KEY = _persisted_secret("api_key", "AETHER_API_KEY")
# remote agents get this one instead. It can only send data in, it cannot read anything or run actions
INGEST_KEY = _persisted_secret("ingest_key", "AETHER_INGEST_KEY")

DEBUG = os.environ.get("AETHER_DEBUG") == "1"
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]", "testserver"] + [
    h for h in os.environ.get("AETHER_ALLOWED_HOSTS", "").split(",") if h
]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "edr",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "aether.urls"
WSGI_APPLICATION = "aether.wsgi.application"
TEMPLATES = []

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": DATA_DIR / "aether.sqlite3",
        "OPTIONS": {
            # WAL lets readers keep working while the collector writes
            "init_command": (
                "PRAGMA journal_mode=WAL;"
                "PRAGMA synchronous=NORMAL;"
                "PRAGMA temp_store=MEMORY;"
                "PRAGMA mmap_size=268435456;"
            ),
            # BEGIN IMMEDIATE avoids deadlocks when a reader upgrades to a writer
            "transaction_mode": "IMMEDIATE",
            "timeout": 30,
        },
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
DATA_UPLOAD_MAX_MEMORY_SIZE = 16 * 1024 * 1024

USE_TZ = True
TIME_ZONE = "UTC"
LANGUAGE_CODE = "en-us"

# the UI is built with `npm run build` into frontend/dist
UI_DIST = BASE_DIR / "frontend" / "dist"
WHITENOISE_ROOT = UI_DIST if UI_DIST.exists() else None
WHITENOISE_INDEX_FILE = True
WHITENOISE_AUTOREFRESH = DEBUG

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["edr.auth.ApiKeyAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["edr.auth.IsOperator"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 100,
    "UNAUTHENTICATED_USER": None,
    "EXCEPTION_HANDLER": "edr.errors.handler",
}

# ---- tunables -----------------------------------------------------------------
AETHER = {
    "COLLECT_INTERVAL": float(os.environ.get("AETHER_INTERVAL", "5")),
    "STATS_INTERVAL": 30.0,            # per-process stats sampling for the baseline
    "MEMSCAN_DELAYS": (2.0, 30.0),     # rescans after first sight, then periodic
    "MEMSCAN_PERIOD": 300.0,
    "MEMSCAN_PER_POLL": 25,
    "ALERT_THRESHOLD": int(os.environ.get("AETHER_ALERT_THRESHOLD", "40")),
    "REVERSE_DNS": os.environ.get("AETHER_REVERSE_DNS") == "1",  # emits DNS queries
    "WATCH_COUNTRIES": [c for c in os.environ.get("AETHER_WATCH_COUNTRIES", "").split(",") if c],
    "JIT_ALLOW": [x.lower() for x in os.environ.get("AETHER_JIT_ALLOW", "").split(",") if x],  # extra JIT hosts
    # same executable region in this many differently named programs = system-wide component, not injection.
    # 0 turns it off
    "SHARED_REGION_MIN": int(os.environ.get("AETHER_SHARED_REGION_MIN", "8")),
    # OS notifications for new processes, so ones shorter than a poll are caught too. 0 = polling only
    "EVENTS": os.environ.get("AETHER_EVENTS", "1") != "0",
    "WATCH_ASNS": [a for a in os.environ.get("AETHER_WATCH_ASNS", "").split(",") if a],
    "RETENTION_DAYS": int(os.environ.get("AETHER_RETENTION_DAYS", "14")),
    "BASELINE_MIN_SAMPLES": 400,
    "BASELINE_RETRAIN_EVERY": 600,
    "YARA_MAX_REGION": 32 * 1024 * 1024,
    "YARA_MAX_TOTAL": 512 * 1024 * 1024,
    "MEMREAD_MAX": 64 * 1024,
    "GEO_DB": DATA_DIR / "geo_asn.csv",  # optional larger dataset (see README)
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"std": {"format": "%(asctime)s %(levelname)-7s %(name)s: %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "std"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {"django.server": {"level": "WARNING"}, "waitress": {"level": "WARNING"}},
}
