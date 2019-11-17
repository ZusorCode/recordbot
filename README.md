# RecordBot
A .env file is required
```
WEB_PORT = 3000  # The port for the main server

BOT_USERNAME = owrecordbot  # The username for the Twitch bot. MUST BE LOWERCASE!!
BOT_OAUTH = oauth:something_here  # The bot oauth token obtained using twitchapps.com/tmi/

TWITCH_CLIENT_ID = a_client_id  # The client ID for a Twitch Application
TWITCH_SECRET = yr2kqvve77mnkvx6x4h6qyqs3hnpnv  # The secret for a Twitch Application

REGULAR_URL = http://localhost:3000  # The base URL
CALLBACK_URL = http://localhost:3000/auth/callback  # The URL for the twitch callback
WEBSOCKET_URL = ws://localhost:3000  # The websocket URL. MUST BE WSS IF THE REST IS HTTPS

WEBHOOK_CALLBACK_URL = http://localhost:3000  # The URL that Webhooks will be registered to
WEBHOOK_PORT = 3001  # The port that webhooks will be received at
```