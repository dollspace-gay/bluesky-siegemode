import os
from flask import Flask, redirect, request, session, url_for, jsonify, render_template, flash
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

# In a real app, you would likely get this from a config file or environment variables.
CLIENT_ID = os.environ.get('CLIENT_ID', "http://127.0.0.1:5000/oauth/client-metadata.json")
REDIRECT_URI = os.environ.get('REDIRECT_URI', "http://127.0.0.1:5000/callback")
AUTHORIZATION_SERVER = "https://bsky.social"

oauth_client = OAuth2Client(
    token_endpoint=f"{AUTHORIZATION_SERVER}/oauth/token",
    authorization_endpoint=f"{AUTHORIZATION_SERVER}/oauth/authorize",
    redirect_uri=REDIRECT_URI,
    auth=PublicApp(CLIENT_ID),
    dpop_bound_access_tokens=True,
)

scheduler = BackgroundScheduler()
scheduler.start()

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
        "scope": "atproto",
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
        scope="atproto",
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
        if token.id_token:
            session['did'] = token.id_token.get('sub')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Error during OAuth callback: {e}")
        flash(f"An error occurred during authentication: {e}", "error")
        return redirect(url_for('index'))

def parse_post_url(post_url: str) -> tuple[str, str] | None:
    parsed_url = urlparse(post_url)
    if parsed_url.hostname != 'bsky.app':
        return None
    path_parts = parsed_url.path.strip('/').split('/')
    if len(path_parts) == 4 and path_parts[0] == 'profile' and path_parts[2] == 'post':
        return path_parts[1], path_parts[3]
    return None

def unsiege_blocks(user_did, token_dict, block_uris):
    """Unblocks a list of users by deleting their block records."""
    print(f"Unsige job started: Unblocking {len(block_uris)} users for {user_did}")
    try:
        token = BearerToken(**token_dict)
        auth = OAuth2AccessTokenAuth(token)

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
                    response = requests.post(
                        "https://bsky.social/xrpc/com.atproto.repo.deleteRecord",
                        json=delete_data,
                        auth=auth
                    )
                    if response.status_code != 200:
                        print(f"Failed to delete block {block_uri}: {response.text}")
                    else:
                        print(f"Successfully deleted block {block_uri}")
    except Exception as e:
        print(f"Error in unsiege_blocks job: {e}")

def unsiege_threadgate(user_did, token_dict, post_rkey):
    """Removes the threadgate from a post."""
    print(f"Unsige job started: Removing threadgate for {user_did} on post {post_rkey}")
    try:
        token = BearerToken(**token_dict)
        auth = OAuth2AccessTokenAuth(token)
        delete_data = {
            'repo': user_did,
            'collection': 'app.bsky.feed.threadgate',
            'rkey': post_rkey,
        }
        response = requests.post(
            "https://bsky.social/xrpc/com.atproto.repo.deleteRecord",
            json=delete_data,
            auth=auth
        )
        response.raise_for_status()
        print(f"Successfully removed threadgate for {user_did} on post {post_rkey}")
    except Exception as e:
        print(f"Error in unsiege_threadgate job: {e}")

@app.route('/siege', methods=['POST'])
def siege():
    if 'token' not in session:
        return redirect(url_for('login'))

    post_url = request.form.get('post_url')
    duration_hours = int(request.form.get('duration', 24))

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

        replies_response = requests.get(f"https://bsky.social/xrpc/app.bsky.feed.getPostThread?uri={post_uri}&depth=1", auth=auth)
        replies_response.raise_for_status()
        thread = replies_response.json()
        repliers = {reply['post']['author']['did'] for reply in thread.get('thread', {}).get('replies', []) if 'post' in reply}

        quotes_response = requests.get(f"https://bsky.social/xrpc/app.bsky.feed.getQuotes?uri={post_uri}", auth=auth)
        quotes_response.raise_for_status()
        quoters = {quote['author']['did'] for quote in quotes_response.json().get('quotes', [])}

        users_to_block = list(repliers.union(quoters) - {post_author_did, user_did})

        block_uris = []
        for did_to_block in users_to_block:
            block_data = {'repo': user_did, 'collection': 'app.bsky.graph.block', 'record': {'subject': did_to_block, 'createdAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}}
            response = requests.post("https://bsky.social/xrpc/com.atproto.repo.createRecord", json=block_data, auth=auth)
            response.raise_for_status()
            block_uris.append(response.json()['uri'])

        threadgate_data = {'repo': user_did, 'collection': 'app.bsky.feed.threadgate', 'rkey': rkey, 'record': {'$type': 'app.bsky.feed.threadgate', 'post': post_uri, 'allow': [], 'createdAt': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}}
        requests.post("https://bsky.social/xrpc/com.atproto.repo.putRecord", json=threadgate_data, auth=auth).raise_for_status()

        run_date = datetime.now() + timedelta(hours=duration_hours)
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