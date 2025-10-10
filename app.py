import os
import logging
from flask import Flask, redirect, request, session, url_for, jsonify, render_template, flash
from flask_session import Session
from flask_wtf import CSRFProtect
from requests_oauth2client import OAuth2Client, BearerToken, PublicApp, OAuth2AccessTokenAuth
from atproto import Client
from urllib.parse import urlparse
import requests
from datetime import datetime, timezone, timedelta
from apscheduler.schedulers.background import BackgroundScheduler

# For a real application, use a secure way to generate and store this key.
# It should be a long, random string and kept secret.
SECRET_KEY = os.environ.get('SECRET_KEY', 'a_super_secret_key_for_dev_only').encode('utf-8')

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Basic logging setup suitable for dev and small deployments
logging.basicConfig(level=os.environ.get('LOG_LEVEL', 'INFO'))
logger = logging.getLogger(__name__)

# Server-side sessions and secure cookie settings
app.config.update(
    SESSION_TYPE=os.environ.get('SESSION_TYPE', 'filesystem'),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax'),
    SESSION_COOKIE_SECURE=(os.environ.get('SESSION_COOKIE_SECURE', '0') == '1'),
)
Session(app)

# CSRF protection for all POST requests
CSRFProtect(app)

# In a real app, you would likely get this from a config file or environment variables.
CLIENT_ID = os.environ.get('CLIENT_ID', "http://127.0.0.1:5000/oauth/client-metadata.json")
REDIRECT_URI = os.environ.get('REDIRECT_URI', "http://127.0.0.1:5000/callback")
AUTHORIZATION_SERVER = os.environ.get('AUTHORIZATION_SERVER', "https://bsky.social")

# Default HTTP timeout for outbound requests
HTTP_TIMEOUT_SECONDS = int(os.environ.get('HTTP_TIMEOUT_SECONDS', '15'))

oauth_client = OAuth2Client(
    token_endpoint=f"{AUTHORIZATION_SERVER}/oauth/token",
    authorization_endpoint=f"{AUTHORIZATION_SERVER}/oauth/authorize",
    redirect_uri=REDIRECT_URI,
    auth=PublicApp(CLIENT_ID),
    dpop_bound_access_tokens=True,
)

scheduler = BackgroundScheduler()

@app.route('/oauth/client-metadata.json')
def client_metadata():
    """Serves the OAuth client metadata."""
    return jsonify({
        "client_id": CLIENT_ID,
        "client_name": "Bluesky Siege Mode",
        "client_uri": "http://127.0.0.1:5000/",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": "openid atproto",
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": True,
    })

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    az_request = oauth_client.authorization_request(
        redirect_uri=REDIRECT_URI,
        scope="openid atproto",
    )
    session['code_verifier'] = az_request.code_verifier
    return redirect(az_request.uri)

@app.route('/callback')
def callback():
    try:
        code_verifier = session.pop('code_verifier', None)
        token: BearerToken = oauth_client.authorization_code(
            request.args['code'],
            code_verifier=code_verifier,
            redirect_uri=REDIRECT_URI
        )
        session['token'] = token.dict()
        session['access_token'] = token.access_token
        # Prefer DID from ID token if present; otherwise, resolve via XRPC
        did_from_id_token = None
        if token.id_token:
            did_from_id_token = token.id_token.get('sub')
        if did_from_id_token:
            session['did'] = did_from_id_token
        else:
            try:
                # Attempt to fetch current session to learn the user's DID
                auth = OAuth2AccessTokenAuth(token)
                resp = requests.get(
                    f"{AUTHORIZATION_SERVER}/xrpc/com.atproto.server.getSession",
                    auth=auth,
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                resp.raise_for_status()
                session_info = resp.json()
                if 'did' in session_info:
                    session['did'] = session_info['did']
            except Exception as inner_e:
                logger.warning("Failed to resolve DID from session endpoint: %s", inner_e)
        return redirect(url_for('index'))
    except Exception as e:
        logger.exception("Error during OAuth callback: %s", e)
        flash(f"An error occurred during authentication: {e}", "error")
        return redirect(url_for('index'))

def parse_post_url(post_url: str) -> tuple[str, str] | None:
    """Extracts (handle_or_did, post_rkey) from a Bluesky post URL.

    Accepts hosts ending with bsky.app and paths of the form:
    /profile/{handle_or_did}/post/{rkey}
    """
    parsed_url = urlparse(post_url)
    hostname = (parsed_url.hostname or '').lower()
    if not hostname.endswith('bsky.app'):
        return None
    path_parts = [p for p in parsed_url.path.strip('/').split('/') if p]
    if len(path_parts) == 4 and path_parts[0] == 'profile' and path_parts[2] == 'post':
        return path_parts[1], path_parts[3]
    return None

def unsiege_blocks(user_did, token_dict, block_uris):
    """Unblocks a list of users by deleting their block records."""
    logger.info("Unsiege job started: Unblocking %d users for %s", len(block_uris), user_did)
    try:
        token = BearerToken(**token_dict)
        auth = OAuth2AccessTokenAuth(token)

        def refresh_auth_on_unauthorized() -> OAuth2AccessTokenAuth | None:
            try:
                if token_dict.get('refresh_token'):
                    new_token = oauth_client.refresh_token(token_dict['refresh_token'])
                    new_token_dict = new_token.dict()
                    token_dict.update(new_token_dict)
                    return OAuth2AccessTokenAuth(BearerToken(**new_token_dict))
            except Exception as refresh_err:
                logger.warning("Token refresh failed during unsiege_blocks: %s", refresh_err)
            return None

        for block_uri in block_uris:
            parts = block_uri.split('/')
            if len(parts) == 5 and parts[0] == 'at:' and parts[1] == '' and parts[3] == 'app.bsky.graph.block':
                repo = parts[2]
                collection = parts[3]
                rkey = parts[4]
                if repo == user_did:
                    delete_data = {
                        'repo': user_did,
                        'collection': collection,
                        'rkey': rkey,
                    }
                    try:
                        response = requests.post(
                            f"{AUTHORIZATION_SERVER}/xrpc/com.atproto.repo.deleteRecord",
                            json=delete_data,
                            auth=auth,
                            timeout=HTTP_TIMEOUT_SECONDS,
                        )
                        if response.status_code == 401:
                            refreshed_auth = refresh_auth_on_unauthorized()
                            if refreshed_auth is not None:
                                auth = refreshed_auth
                                response = requests.post(
                                    f"{AUTHORIZATION_SERVER}/xrpc/com.atproto.repo.deleteRecord",
                                    json=delete_data,
                                    auth=auth,
                                    timeout=HTTP_TIMEOUT_SECONDS,
                                )
                        response.raise_for_status()
                        logger.info("Successfully deleted block %s", block_uri)
                    except Exception as req_err:
                        logger.warning("Failed to delete block %s: %s", block_uri, req_err)
    except Exception as e:
        logger.exception("Error in unsiege_blocks job: %s", e)

def unsiege_threadgate(user_did, token_dict, post_rkey):
    """Removes the threadgate from a post."""
    logger.info("Unsiege job started: Removing threadgate for %s on post %s", user_did, post_rkey)
    try:
        token = BearerToken(**token_dict)
        auth = OAuth2AccessTokenAuth(token)

        def refresh_auth_on_unauthorized() -> OAuth2AccessTokenAuth | None:
            try:
                if token_dict.get('refresh_token'):
                    new_token = oauth_client.refresh_token(token_dict['refresh_token'])
                    new_token_dict = new_token.dict()
                    token_dict.update(new_token_dict)
                    return OAuth2AccessTokenAuth(BearerToken(**new_token_dict))
            except Exception as refresh_err:
                logger.warning("Token refresh failed during unsiege_threadgate: %s", refresh_err)
            return None

        delete_data = {
            'repo': user_did,
            'collection': 'app.bsky.feed.threadgate',
            'rkey': post_rkey,
        }
        response = requests.post(
            f"{AUTHORIZATION_SERVER}/xrpc/com.atproto.repo.deleteRecord",
            json=delete_data,
            auth=auth,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        if response.status_code == 401:
            refreshed_auth = refresh_auth_on_unauthorized()
            if refreshed_auth is not None:
                auth = refreshed_auth
                response = requests.post(
                    f"{AUTHORIZATION_SERVER}/xrpc/com.atproto.repo.deleteRecord",
                    json=delete_data,
                    auth=auth,
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
        response.raise_for_status()
        logger.info("Successfully removed threadgate for %s on post %s", user_did, post_rkey)
    except Exception as e:
        logger.exception("Error in unsiege_threadgate job: %s", e)

@app.route('/siege', methods=['POST'])
def siege():
    if 'token' not in session:
        return redirect(url_for('login'))

    post_url = request.form.get('post_url', '').strip()
    # Validate and clamp duration safely
    try:
        duration_hours = int(request.form.get('duration', 24))
    except Exception:
        flash("Invalid duration. Enter 1–72 hours.", "error")
        return redirect(url_for('index'))
    if duration_hours < 1 or duration_hours > 72:
        flash("Invalid duration. Enter 1–72 hours.", "error")
        return redirect(url_for('index'))

    parsed_info = parse_post_url(post_url)
    if not parsed_info:
        flash("Invalid Bluesky post URL.", "error")
        return redirect(url_for('index'))

    handle, rkey = parsed_info
    user_did = session['did']

    try:
        token = BearerToken(**session['token'])
        auth = OAuth2AccessTokenAuth(token)
        client = Client()
        profile = client.get_profile(handle)
        post_author_did = profile.did
        post_uri = f"at://{post_author_did}/app.bsky.feed.post/{rkey}"

        replies_response = requests.get(
            f"{AUTHORIZATION_SERVER}/xrpc/app.bsky.feed.getPostThread",
            params={"uri": post_uri, "depth": 1},
            auth=auth,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        replies_response.raise_for_status()
        thread = replies_response.json()
        repliers = {reply['post']['author']['did'] for reply in thread.get('thread', {}).get('replies', []) if 'post' in reply}

        quotes_response = requests.get(
            f"{AUTHORIZATION_SERVER}/xrpc/app.bsky.feed.getQuotes",
            params={"uri": post_uri},
            auth=auth,
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        quotes_response.raise_for_status()
        quoters = {quote['author']['did'] for quote in quotes_response.json().get('quotes', [])}

        users_to_block = list(repliers.union(quoters) - {post_author_did, user_did})

        block_uris = []
        for did_to_block in users_to_block:
            block_data = {
                'repo': user_did,
                'collection': 'app.bsky.graph.block',
                'record': {
                    'subject': did_to_block,
                    'createdAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                }
            }
            response = requests.post(
                f"{AUTHORIZATION_SERVER}/xrpc/com.atproto.repo.createRecord",
                json=block_data,
                auth=auth,
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            block_uris.append(response.json()['uri'])

        threadgate_data = {
            'repo': user_did,
            'collection': 'app.bsky.feed.threadgate',
            'rkey': rkey,
            'record': {
                '$type': 'app.bsky.feed.threadgate',
                'post': post_uri,
                'allow': [],
                'createdAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            }
        }
        requests.post(
            f"{AUTHORIZATION_SERVER}/xrpc/com.atproto.repo.putRecord",
            json=threadgate_data,
            auth=auth,
            timeout=HTTP_TIMEOUT_SECONDS,
        ).raise_for_status()

        # Start scheduler safely only once in this process before scheduling
        try:
            if not getattr(scheduler, 'running', False):
                scheduler.start()
        except Exception as start_err:
            logger.warning("Scheduler start issue (continuing): %s", start_err)

        run_date = datetime.now(timezone.utc) + timedelta(hours=duration_hours)
        scheduler.add_job(unsiege_blocks, 'date', run_date=run_date, args=[user_did, session['token'], block_uris])
        scheduler.add_job(unsiege_threadgate, 'date', run_date=run_date, args=[user_did, session['token'], rkey])

        flash(f"Siege mode activated for {duration_hours} hours! Blocked {len(users_to_block)} users and disabled replies. Actions will be reversed automatically.", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "error")

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)