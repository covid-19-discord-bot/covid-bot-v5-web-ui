import os
from flask import Flask, g, session, redirect, request, url_for, jsonify
from requests_oauthlib import OAuth2Session
from secrets import token_urlsafe

OAUTH2_CLIENT_ID = os.environ['OAUTH2_CLIENT_ID']
OAUTH2_CLIENT_SECRET = os.environ['OAUTH2_CLIENT_SECRET']
OAUTH2_REDIRECT_URI = 'http://20.43.17.201:5000/callback'

API_BASE_URL = os.environ.get('API_BASE_URL', 'https://discord.com/api/v8')
AUTHORIZATION_BASE_URL = API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = API_BASE_URL + '/oauth2/token'

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = OAUTH2_CLIENT_SECRET


if 'http://' in OAUTH2_REDIRECT_URI:
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'true'


def token_updater(token):
    session['oauth2_token'] = token


def make_session(token: str = None, state: str = None, scope=None) -> OAuth2Session:
    return OAuth2Session(
        client_id=OAUTH2_CLIENT_ID,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=OAUTH2_REDIRECT_URI,
        auto_refresh_kwargs={
            'client_id': OAUTH2_CLIENT_ID,
            'client_secret': OAUTH2_CLIENT_SECRET,
        },
        auto_refresh_url=TOKEN_URL,
        token_updater=token_updater)


@app.before_request
def set_domain_session():
    session['domain'] = request.headers['Host']


@app.route('/')
def index():
    scope = request.args.get(
        'scope',
        'identify guilds')
    state = token_urlsafe()
    discord = make_session(scope=scope.split(' '), state=state)
    authorization_url = discord.authorization_url(AUTHORIZATION_BASE_URL, state=state)
    session['oauth2_state'] = state
    return redirect(authorization_url[0])


@app.route('/callback')
def callback():
    if request.values.get('error'):
        return request.values['error']
    discord = make_session(state=session.get('oauth2_state'),
                           token=request.args.get('code'))
    token = discord.fetch_token(
        TOKEN_URL,
        code=request.args.get('code'),
        client_secret=OAUTH2_CLIENT_SECRET)
    session['oauth2_token'] = token
    return redirect(url_for('.me'))


@app.route('/me')
def me():
    discord = make_session(token=session.get('oauth2_token'))
    user = discord.get(API_BASE_URL + '/users/@me').json()
    guilds = discord.get(API_BASE_URL + '/users/@me/guilds').json()
    manage_guilds = []
    for guild in guilds:
        if (int(guild["permissions"]) & 0x20) == 0x20 or guild["owner"]:
            manage_guilds.append(guild)
    ret_str = "{name}#{discrm} ({id}) has the manage_guild permission in the following guilds:\n".format(
        name=user["username"], discrm=user["discriminator"], id=user["id"]
    )
    for guild in manage_guilds:
        ret_str += "{name} ({id})\n".format(name=guild["name"], id=guild["id"])
    return ret_str


if __name__ == '__main__':
    app.run(host="0.0.0.0")
