import json
import os
from secrets import token_urlsafe
from typing import Optional

import requests
from flask import Flask, session, redirect, request, url_for, render_template, flash, abort
from requests import Response
from requests_oauthlib import OAuth2Session

app = Flask(__name__)
app.debug = True


class InvalidUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        super().__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


with open("config.json", "r") as f:
    config = json.load(f)

app.config["SECRET_KEY"] = config["app"]["secret_key"]

if "http://" in config["oauth2"]["redirect_uri"]:
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # !!!!! DO NOT ENABLE IN PRODUCTION !!!!!

client_id = config["oauth2"]["client_id"]
client_secret = config["oauth2"]["client_secret"]
redirect_uri = config["oauth2"]["redirect_uri"]
discord_api_base_url = "https://discord.com/api"
authorization_base_url = discord_api_base_url + '/oauth2/authorize'
token_url = discord_api_base_url + '/oauth2/token'

bot_api_base_url = config["bot"]["base_url"]
bot_auth_token = config["bot"]["token"]


def bot_api_request(url: str, method: Optional[str] = "GET") -> Response:
    headers = {
        "Authorization": bot_auth_token
    }
    if method == "GET":
        return requests.get(bot_api_base_url + url, headers=headers)
    elif method == "POST":
        return requests.post(bot_api_base_url + url, headers=headers)
    else:
        raise NotImplementedError("The only supported bot API methods are GET and POST!")


def exchange_code(code):
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'scope': 'identify guilds'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post('%s/oauth2/token' % discord_api_base_url, data=data, headers=headers)
    r.raise_for_status()
    return r.json()["access_token"]


def token_updater(token):
    session['oauth2_token'] = token


def make_session(token=None, state=None, scope=None):
    return OAuth2Session(
        client_id=client_id,
        token=token,
        state=state,
        scope=scope,
        redirect_uri=redirect_uri,
        auto_refresh_kwargs={
            'client_id': client_id,
            'client_secret': client_secret,
        },
        auto_refresh_url=token_url,
        token_updater=token_updater)


def get_user_and_guilds(token: str) -> tuple:
    discord = make_session(token=token)
    user = discord.get(discord_api_base_url + '/users/@me').json()
    guilds = discord.get(discord_api_base_url + '/users/@me/guilds').json()
    return user, guilds


@app.before_request
def set_domain_session():
    session['domain'] = request.headers['Host']


@app.route('/')
def index():
    return render_template("index.html", in_out="Login")


@app.route('/invite')
def invite():
    return render_template("invite.html", in_out="Login")


@app.errorhandler(404)
def http_404():
    return render_template("404.html")


@app.errorhandler(403)
def http_403():
    return render_template("403.html")


@app.route('/login')
def login():
    if session.get("oauth2_token"):
        del session["oauth2_token"]
        flash("You were logged out successfully.")  # to keep users from being confused flash a logout msg
        return redirect("/")  # redirect home after deleting the session's OAuth2 token
    else:
        discord = make_session(scope=["identify", "guilds"])
        authorization_url, state = discord.authorization_url(authorization_base_url)
        session['oauth2_state'] = state
        return redirect(authorization_url)


@app.route("/callback")
def oauth_callback():
    if request.values.get('error'):
        return f"Discord returned a error while sending the tokens! {request.values['error']}<br>" \
               f"Click <a href=\"{url_for('.login')}\">here</a> to try again."
    discord = make_session(state=session.get('oauth2_state'), token=request.values.get('code'))
    token = discord.fetch_token(
        token_url,
        client_secret=client_secret,
        code=request.args.get("code"))
    session['oauth2_token'] = token
    return redirect(url_for(".dashboard"))


@app.route('/me')
def me():
    discord = make_session(token=session.get('oauth2_token'))
    user = discord.get(discord_api_base_url + '/users/@me').json()
    guilds = discord.get(discord_api_base_url + '/users/@me/guilds').json()
    manage_guilds = []
    for guild in guilds:
        if guild["owner"] or (int(guild["permissions"]) & 0x20) == 0x20:
            manage_guilds.append(guild)
    ret_str = "{name} ({id}) has the manage_guild permission in the following guilds:\n".format(
        name=f"{user['username']}#{user['discriminator']}", id=user["id"]
    )
    for guild in manage_guilds:
        ret_str += "{name} ({id})\n".format(name=guild["name"], id=guild["id"])
    return ret_str


@app.route("/dashboard")
def dashboard():
    if not session.get("oauth2_token"):  # force the user to log in if they aren't already
        return redirect(url_for(".login"))
    bot_data = bot_api_request("protected/basic_info/")
    try:
        bot_data.raise_for_status()
        server_count = bot_data.json()["server_count"]
        channel_count = bot_data.json()["channel_count"]
    except requests.exceptions.RequestException:
        server_count = "unknown"
        channel_count = "unknown"
    user, guilds = get_user_and_guilds(session.get('oauth2_token'))
    guild_list = []
    for guild in guilds:
        guild_list.append(str(guild["id"]))
    try:
        accessible_guilds_request = bot_api_request(f"protected/bot_is_in_servers/{'-'.join(guild_list)}")
        accessible_guilds_request.raise_for_status()
        accessible_guilds = accessible_guilds_request.json()
    except requests.exceptions.RequestException:
        accessible_guilds = []
    servers = []
    allowed_servers = [i for i in guilds if int(i["id"]) in accessible_guilds]
    for guild, i in zip(allowed_servers, range(1, len(allowed_servers))):
        gd = {
            "id": guild["id"],
            "name": guild["name"]
        }
        if guild.get("icon", None):
            gd["icon_url"] = f"https://cdn.discordapp.com/icons/{guild['id']}/{guild['icon']}.png?size=1024"
        else:
            gd["icon_url"] = None
        servers.append([gd, i])

    return render_template("dashboard.html", in_out="Logout", servers=servers, server_count=server_count,
                           channel_count=channel_count, username=user['username'])


@app.route("/manage/<guild_id:int>")
def manage_guild(guild_id):
    if not session.get("oauth2_token"):  # force the user to log in if they aren't already
        return redirect(url_for(".login"))
    try:
        accessible_guilds_request = bot_api_request(f"protected/bot_is_in_server/{guild_id}")
        accessible_guilds_request.raise_for_status()
        is_in_guild = accessible_guilds_request.json()["is_in_server"]
    except requests.exceptions.RequestException:
        abort(500)
    if not is_in_guild:
        abort(404)
    # we now know the bot is in this guild
    # time to check if the user is in guild and has perms


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=443, ssl_context='adhoc', debug=False)
