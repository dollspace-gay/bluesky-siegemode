import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.dirname(__file__), "app.db"))

SCHEMA_SQL = r"""
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS user_notification_prefs (
  did TEXT PRIMARY KEY,
  prefs_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_push_tokens (
  did TEXT NOT NULL,
  service_did TEXT,
  device_token TEXT NOT NULL,
  app_id TEXT,
  platform TEXT,
  disabled INTEGER DEFAULT 0,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (did, device_token)
);

CREATE TABLE IF NOT EXISTS activity_subscriptions (
  did TEXT NOT NULL,
  collection TEXT NOT NULL,
  active INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (did, collection)
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  notification_json TEXT NOT NULL,
  is_read INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notifications_did_created ON notifications(did, created_at DESC);

CREATE TABLE IF NOT EXISTS actor_prefs (
  did TEXT PRIMARY KEY,
  prefs_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bookmarks (
  did TEXT NOT NULL,
  uri TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (did, uri)
);

CREATE TABLE IF NOT EXISTS video_jobs (
  job_id TEXT PRIMARY KEY,
  did TEXT NOT NULL,
  status TEXT NOT NULL,
  progress INTEGER DEFAULT 0,
  message TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS interactions_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  did TEXT NOT NULL,
  interactions_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def init_db() -> None:
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    with connect() as conn:
        conn.executescript(SCHEMA_SQL)
        conn.commit()


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    try:
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        conn.close()
