import json
from flask import Blueprint, request, jsonify, session, current_app
from requests_oauth2client import BearerToken, OAuth2AccessTokenAuth
from typing import Any, Dict
from db import connect, utc_now_iso

xrpc_bp = Blueprint('xrpc', __name__)


def _require_auth() -> OAuth2AccessTokenAuth:
    token_dict = session.get('token')
    if not token_dict:
        return None
    try:
        token = BearerToken(**token_dict)
        return OAuth2AccessTokenAuth(token)
    except Exception:
        return None


# ---------------------
# Notification endpoints
# ---------------------
@xrpc_bp.route('/app.bsky.notification.listNotifications', methods=['GET'])
def list_notifications():
    did = session.get('did')
    if not did:
        return jsonify({"notifications": [], "cursor": None}), 200
    limit = int(request.args.get('limit', 50))
    cursor = request.args.get('cursor')
    with connect() as conn:
        params = [did]
        query = "SELECT id, notification_json, is_read, created_at FROM notifications WHERE did=?"
        if cursor:
            try:
                cursor_id = int(cursor)
                query += " AND id < ?"
                params.append(cursor_id)
            except Exception:
                pass
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        items = [json.loads(r['notification_json']) for r in rows]
        next_cursor = str(rows[-1]['id']) if rows else None
        return jsonify({"notifications": items, "cursor": next_cursor}), 200


@xrpc_bp.route('/app.bsky.notification.getUnreadCount', methods=['GET'])
def get_unread_count():
    did = session.get('did')
    if not did:
        return jsonify({"count": 0}), 200
    with connect() as conn:
        row = conn.execute(
            "SELECT COUNT(1) AS c FROM notifications WHERE did=? AND is_read=0",
            (did,),
        ).fetchone()
        return jsonify({"count": int(row['c'] or 0)}), 200


@xrpc_bp.route('/app.bsky.notification.getPreferences', methods=['GET'])
def get_notification_prefs():
    did = session.get('did')
    if not did:
        return jsonify({"preferences": []}), 200
    with connect() as conn:
        row = conn.execute(
            "SELECT prefs_json FROM user_notification_prefs WHERE did=?",
            (did,),
        ).fetchone()
        prefs = json.loads(row['prefs_json']) if row else []
        return jsonify({"preferences": prefs}), 200


@xrpc_bp.route('/app.bsky.notification.putPreferencesV2', methods=['POST'])
def put_notification_prefs_v2():
    did = session.get('did')
    if not did:
        return jsonify({"ok": True}), 200
    data = request.get_json(force=True, silent=True) or {}
    prefs = data.get('preferences', [])
    with connect() as conn:
        conn.execute(
            "INSERT INTO user_notification_prefs(did, prefs_json, updated_at) VALUES(?, ?, ?)\n"
            "ON CONFLICT(did) DO UPDATE SET prefs_json=excluded.prefs_json, updated_at=excluded.updated_at",
            (did, json.dumps(prefs), utc_now_iso()),
        )
        conn.commit()
    return jsonify({"ok": True}), 200


@xrpc_bp.route('/app.bsky.notification.listActivitySubscriptions', methods=['GET'])
def list_activity_subscriptions():
    did = session.get('did')
    if not did:
        return jsonify({"subscriptions": []}), 200
    with connect() as conn:
        rows = conn.execute(
            "SELECT collection, active FROM activity_subscriptions WHERE did=?",
            (did,),
        ).fetchall()
        subs = [{"collection": r['collection'], "active": bool(r['active'])} for r in rows]
        return jsonify({"subscriptions": subs}), 200


@xrpc_bp.route('/app.bsky.notification.putActivitySubscription', methods=['POST'])
def put_activity_subscription():
    did = session.get('did')
    if not did:
        return jsonify({"ok": True}), 200
    data = request.get_json(force=True, silent=True) or {}
    collection = data.get('collection')
    active = bool(data.get('active', True))
    if not collection:
        return jsonify({"error": "collection required"}), 400
    with connect() as conn:
        conn.execute(
            "INSERT INTO activity_subscriptions(did, collection, active, updated_at) VALUES(?, ?, ?, ?)\n"
            "ON CONFLICT(did, collection) DO UPDATE SET active=excluded.active, updated_at=excluded.updated_at",
            (did, collection, 1 if active else 0, utc_now_iso()),
        )
        conn.commit()
    return jsonify({"ok": True}), 200


@xrpc_bp.route('/app.bsky.notification.registerPush', methods=['POST'])
def register_push():
    did = session.get('did')
    if not did:
        return jsonify({"ok": True}), 200
    data = request.get_json(force=True, silent=True) or {}
    device_token = data.get('deviceToken')
    if not device_token:
        return jsonify({"error": "deviceToken required"}), 400
    with connect() as conn:
        conn.execute(
            "INSERT INTO notification_push_tokens(did, service_did, device_token, app_id, platform, disabled, updated_at)\n"
            " VALUES(?, ?, ?, ?, ?, 0, ?)\n"
            "ON CONFLICT(did, device_token) DO UPDATE SET service_did=excluded.service_did, app_id=excluded.app_id, platform=excluded.platform, disabled=0, updated_at=excluded.updated_at",
            (
                did,
                data.get('serviceDid'),
                device_token,
                data.get('appId'),
                data.get('platform'),
                utc_now_iso(),
            ),
        )
        conn.commit()
    return jsonify({"ok": True}), 200


@xrpc_bp.route('/app.bsky.notification.unregisterPush', methods=['POST'])
def unregister_push():
    did = session.get('did')
    if not did:
        return jsonify({"ok": True}), 200
    data = request.get_json(force=True, silent=True) or {}
    device_token = data.get('deviceToken')
    if not device_token:
        return jsonify({"error": "deviceToken required"}), 400
    with connect() as conn:
        conn.execute(
            "UPDATE notification_push_tokens SET disabled=1, updated_at=? WHERE did=? AND device_token=?",
            (utc_now_iso(), did, device_token),
        )
        conn.commit()
    return jsonify({"ok": True}), 200


# ---------------------
# Actor preferences (local storage, note: differs from upstream which writes to PDS)
# ---------------------
@xrpc_bp.route('/app.bsky.actor.getPreferences', methods=['GET'])
def get_actor_prefs():
    did = session.get('did')
    if not did:
        return jsonify({"preferences": []}), 200
    with connect() as conn:
        row = conn.execute("SELECT prefs_json FROM actor_prefs WHERE did=?", (did,)).fetchone()
        prefs = json.loads(row['prefs_json']) if row else []
        return jsonify({"preferences": prefs}), 200


@xrpc_bp.route('/app.bsky.actor.putPreferences', methods=['POST'])
def put_actor_prefs():
    did = session.get('did')
    if not did:
        return jsonify({"ok": True}), 200
    data = request.get_json(force=True, silent=True) or {}
    prefs = data.get('preferences', [])
    with connect() as conn:
        conn.execute(
            "INSERT INTO actor_prefs(did, prefs_json, updated_at) VALUES(?, ?, ?)\n"
            "ON CONFLICT(did) DO UPDATE SET prefs_json=excluded.prefs_json, updated_at=excluded.updated_at",
            (did, json.dumps(prefs), utc_now_iso()),
        )
        conn.commit()
    return jsonify({"ok": True}), 200


# ---------------------
# Bookmarks
# ---------------------
@xrpc_bp.route('/app.bsky.bookmark.createBookmark', methods=['POST'])
def create_bookmark():
    did = session.get('did')
    if not did:
        return jsonify({"ok": True}), 200
    data = request.get_json(force=True, silent=True) or {}
    uri = data.get('uri')
    if not uri:
        return jsonify({"error": "uri required"}), 400
    with connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO bookmarks(did, uri, created_at) VALUES(?, ?, ?)",
            (did, uri, utc_now_iso()),
        )
        conn.commit()
    return jsonify({"ok": True}), 200


@xrpc_bp.route('/app.bsky.bookmark.deleteBookmark', methods=['POST'])
def delete_bookmark():
    did = session.get('did')
    if not did:
        return jsonify({"ok": True}), 200
    data = request.get_json(force=True, silent=True) or {}
    uri = data.get('uri')
    if not uri:
        return jsonify({"error": "uri required"}), 400
    with connect() as conn:
        conn.execute("DELETE FROM bookmarks WHERE did=? AND uri=?", (did, uri))
        conn.commit()
    return jsonify({"ok": True}), 200


@xrpc_bp.route('/app.bsky.bookmark.getBookmarks', methods=['GET'])
def get_bookmarks():
    did = session.get('did')
    if not did:
        return jsonify({"bookmarks": [], "cursor": None}), 200
    limit = int(request.args.get('limit', 50))
    cursor = request.args.get('cursor')
    with connect() as conn:
        params = [did]
        query = "SELECT uri, created_at FROM bookmarks WHERE did=?"
        if cursor:
            try:
                query += " AND created_at < ?"
                params.append(cursor)
            except Exception:
                pass
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        items = [{"uri": r['uri'], "createdAt": r['created_at']} for r in rows]
        next_cursor = rows[-1]['created_at'] if rows else None
        return jsonify({"bookmarks": items, "cursor": next_cursor}), 200


# ---------------------
# Unspecced endpoints - minimal placeholders per requirements
# ---------------------
@xrpc_bp.route('/app.bsky.unspecced.getPostThreadV2', methods=['GET'])
@xrpc_bp.route('/app.bsky.unspecced.getPostThreadOtherV2', methods=['GET'])
def get_post_thread_v2():
    return jsonify({"thread": {}, "replies": []}), 200


@xrpc_bp.route('/app.bsky.unspecced.getOnboardingSuggestedStarterPacks', methods=['GET'])
def get_onboarding_suggested_starter_packs():
    return jsonify({"starterPacks": []}), 200


@xrpc_bp.route('/app.bsky.unspecced.getTaggedSuggestions', methods=['GET'])
def get_tagged_suggestions():
    return jsonify({"suggestions": []}), 200


@xrpc_bp.route('/app.bsky.unspecced.getTrendingTopics', methods=['GET'])
@xrpc_bp.route('/app.bsky.unspecced.getTrends', methods=['GET'])
def get_trending_topics():
    return jsonify({"topics": []}), 200


@xrpc_bp.route('/app.bsky.unspecced.getConfig', methods=['GET'])
def get_unspecced_config():
    # Provide static config example
    return jsonify({
        "media": {
            "imageMaxBytes": 5000000,
            "videoMaxBytes": 200000000,
        }
    }), 200


# ---------------------
# Graph parity helpers
# ---------------------
@xrpc_bp.route('/app.bsky.graph.getActorStarterPacks', methods=['GET'])
def get_actor_starter_packs():
    # Return empty starter packs, per requirements
    return jsonify({"feeds": [], "starterPacks": []}), 200


@xrpc_bp.route('/app.bsky.graph.getStarterPacksWithMembership', methods=['GET'])
def get_starter_packs_with_membership():
    return jsonify({"starterPacks": []}), 200


@xrpc_bp.route('/app.bsky.graph.searchStarterPacks', methods=['GET'])
def search_starter_packs():
    return jsonify({"starterPacks": []}), 200


# ---------------------
# Video
# ---------------------
@xrpc_bp.route('/app.bsky.video.getUploadLimits', methods=['GET'])
def get_upload_limits():
    return jsonify({
        "image": {"maxBytes": 5000000},
        "video": {"maxBytes": 200000000}
    }), 200


@xrpc_bp.route('/app.bsky.video.getJobStatus', methods=['GET'])
def get_job_status():
    job_id = request.args.get('jobId')
    if not job_id:
        return jsonify({"error": "jobId required"}), 400
    with connect() as conn:
        row = conn.execute("SELECT status, progress, message, updated_at FROM video_jobs WHERE job_id=?", (job_id,)).fetchone()
        if not row:
            return jsonify({"status": "unknown"}), 200
        return jsonify({
            "status": row['status'],
            "progress": int(row['progress'] or 0),
            "message": row['message'],
            "updatedAt": row['updated_at'],
        }), 200


# ---------------------
# Feed interactions
# ---------------------
@xrpc_bp.route('/app.bsky.feed.sendInteractions', methods=['POST'])
def send_interactions():
    did = session.get('did')
    data = request.get_json(force=True, silent=True) or {}
    with connect() as conn:
        conn.execute(
            "INSERT INTO interactions_log(did, interactions_json, created_at) VALUES(?, ?, ?)",
            (did or "", json.dumps(data), utc_now_iso()),
        )
        conn.commit()
    return jsonify({"ok": True}), 200
