let TwitchBot = require('twitch-bot');

let passport = require("passport");
let OAuth2Strategy = require("passport-oauth").OAuth2Strategy;

const Database = require('better-sqlite3');
const db = new Database('main.db');
let express = require("express");
let session = require("express-session");
let request = require("request");
let crypto = require("crypto");
let csrf = require('csurf');
require('dotenv').config();
const helmet = require('helmet');
let cookieParser = require('cookie-parser');
let csrfProtection = csrf({ cookie: true});
let sanitizeHtml = require('sanitize-html');
const TwitchWebhook = require('twitch-webhook');
const bodyParser = require('body-parser');
let ejs = require('ejs');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(helmet());

let expressWs = require('express-ws')(app);

const WEB_PORT = process.env.WEB_PORT;

const BOT_USERNAME = process.env.BOT_USERNAME;
const BOT_OAUTH = process.env.BOT_OAUTH;

const TWITCH_CLIENT_ID = process.env.TWITCH_CLIENT_ID;
const TWITCH_SECRET = process.env.TWITCH_SECRET;

const REGULAR_URL = process.env.REGULAR_URL;
const CALLBACK_URL = process.env.CALLBACK_URL;
const WEBSOCKET_URL = process.env.WEBSOCKET_URL;



const WEBHOOK_CALLBACK_URL = process.env.WEBHOOK_CALLBACK_URL;
const WEBHOOK_PORT = process.env.WEBHOOK_PORT;

const SESSION_SECRET = crypto.randomBytes(20).toString('hex');
const WEBHOOK_SECRET = crypto.randomBytes(20).toString('hex');

const twitchWebhook = new TwitchWebhook({
    client_id: TWITCH_CLIENT_ID,
    callback: WEBHOOK_CALLBACK_URL,
    secret: WEBHOOK_SECRET,
    lease_seconds: 259200,
    listen: {
        port: WEBHOOK_PORT,
    }
});


// Setup Twitch Bot with Username and Oauth
const Bot = new TwitchBot({
    username: BOT_USERNAME,
    oauth: BOT_OAUTH,
    channels: []
});



app.use(session({secret: SESSION_SECRET, resave: false, saveUninitialized: false}));
app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', 'ejs');

// All login stuff
OAuth2Strategy.prototype.userProfile = function (accessToken, done) {
    let options = {
        url: 'https://api.twitch.tv/helix/users',
        method: 'GET',
        headers: {
            'Client-ID': TWITCH_CLIENT_ID,
            'Accept': 'application/vnd.twitchtv.v5+json',
            'Authorization': 'Bearer ' + accessToken
        }
    };

    request(options, function (error, response, body) {
        if (response && response.statusCode === 200) {
            done(null, JSON.parse(body));
        } else {
            done(JSON.parse(body));
        }
    });
}

passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

passport.use('twitch', new OAuth2Strategy({
        authorizationURL: 'https://id.twitch.tv/oauth2/authorize',
        tokenURL: 'https://id.twitch.tv/oauth2/token',
        clientID: TWITCH_CLIENT_ID,
        clientSecret: TWITCH_SECRET,
        callbackURL: CALLBACK_URL,
        state: true
    },
    function (accessToken, refreshToken, profile, done) {
        profile.accessToken = accessToken;
        profile.refreshToken = refreshToken;
        done(null, profile);
    }
));

app.get('/auth', passport.authenticate('twitch', {scope: ''}));
app.get('/auth/callback', passport.authenticate('twitch', {successRedirect: '/manage', failureRedirect: '/'}));
app.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});

// Returns true if the user is logged in
function check_authorized(req) {
    return req.session && req.session.passport && req.session.passport.user
}


// End login stuff


function alert_client(user_id) {
    const user = db.prepare("SELECT * FROM users WHERE user_id = ?").get(user_id);
    expressWs.getWss().clients.forEach(function (client) {
        if (client.id === user.token && client.is_subscribed) {
            client.send("record_updated")
        }
    })
}


function refresh_client(token) {
    expressWs.getWss().clients.forEach(function (client) {
        if (client.id === token) {
            client.send("refresh")
        }
    })
}

function channel_to_user_id(channel) {
    const user = db.prepare("SELECT user_id FROM users WHERE username = ? COLLATE NOCASE").get(channel.replace("#", ""));
    if (user !== undefined) {
        return user.user_id
    }
}

function record_win(channel) {
    const user_id = channel_to_user_id(channel);
    alert_client(user_id);
    db.prepare("INSERT INTO events VALUES (?, ?, ?)").run(channel_to_user_id(channel), "win", Date.now());
}

function record_loss(channel) {
    const user_id = channel_to_user_id(channel);
    alert_client(user_id);
    db.prepare("INSERT INTO events VALUES (?, ?, ?)").run(channel_to_user_id(channel), "loss", Date.now());
}

function record_draw(channel) {
    const user_id = channel_to_user_id(channel);
    alert_client(user_id);
    db.prepare("INSERT INTO events VALUES (?, ?, ?)").run(channel_to_user_id(channel), "draw", Date.now());
}

function record_reset(channel) {
    const user_id = channel_to_user_id(channel);
    alert_client(user_id);
    db.prepare("INSERT INTO events VALUES (?, ?, ?)").run(channel_to_user_id(channel), "reset", Date.now());
}

function record_reset_auto(channel_id, time) {
    let duplicate_event = db.prepare("SELECT * FROM events WHERE user_id = ? AND type = 'reset_auto' AND time = ?").get(channel_id, time);
    if (duplicate_event === undefined) {
        alert_client(channel_id);
        db.prepare("INSERT INTO events VALUES (?, ?, ?)").run(channel_id, "reset_auto", Date.now());
    }
}


twitchWebhook.on('streams', ({ event }) => {
    console.debug("Got webhook event " + event);
    if (event.data.length !== 0) {
        const user_id = event.data[0].user_id;
        const time = new Date(event.data[0].started_at).getTime();
        record_reset_auto(user_id, time)
    }
});

twitchWebhook.on('unsubscribe', (obj) => {
    twitchWebhook.subscribe(obj['hub.topic'])
});

process.on('SIGINT', () => {
    // unsubscribe from all topics
    console.log("Unsubscribing from Webhooks");
    twitchWebhook.unsubscribe('*');
    process.exit(0)
});



function record_from_channel_id_and_date(channel_id, date) {
    const record_events = db.prepare("SELECT * FROM events WHERE user_id = ? AND time > ?").all(channel_id, date);

    const win_amount = record_events.filter(event => event.type === "win").length;
    const loss_amount = record_events.filter(event => event.type === "loss").length;
    const draw_amount = record_events.filter(event => event.type === "draw").length;
    return {win: win_amount, loss: loss_amount, draw: draw_amount};
}

function get_simple_record(channel_id) {
    // Check for the most recent reset event for that user
    let recent_reset = db.prepare("SELECT * FROM events WHERE time = (SELECT max(time) FROM events WHERE type = 'reset' AND user_id = ?)").get(channel_id);
    // Janky
    // If there has not been a reset just set it to 0 to not cause errors.
    if (recent_reset === undefined) {
        recent_reset = {time: 0}
    }
    return record_from_channel_id_and_date(channel_id, recent_reset.time);
}



function calculate_record(channel_id) {
        const wants_auto_reset = !!db.prepare("SELECT record_reset FROM users WHERE user_id = ?").get(channel_id).record_reset;
        if (wants_auto_reset) {
            // Check for the most recent reset event for that user
            let reset = db.prepare("SELECT time FROM events WHERE time = (SELECT max(time) FROM events WHERE type = 'reset' OR type = 'reset_auto' AND user_id = ?)").get(channel_id);
            if (reset === undefined) {
                return get_simple_record(channel_id)
            }
            return record_from_channel_id_and_date(channel_id, reset.time);
        } else {
            return get_simple_record(channel_id)
        }
}

Bot.on('message', chatter => {
    if (chatter.mod || chatter.badges.broadcaster === 1) {
        if (chatter.message === "!w" || chatter.message === "!win") {
            Bot.say("Recorded win!", chatter.channel);
            record_win(chatter.channel)
        } else if (chatter.message === "!l" || chatter.message === "!loss") {
            Bot.say("Recorded loss!", chatter.channel);
            record_loss(chatter.channel)
        } else if (chatter.message === "!d" || chatter.message === "!draw") {
            Bot.say("Recorded draw!", chatter.channel);
            record_draw(chatter.channel)
        } else if (chatter.message === "!reset") {
            Bot.say("Reset record!", chatter.channel);
            record_reset(chatter.channel)
        }
    }

    if (chatter.message === "!r" || chatter.message === "!wl" || chatter.message === "!record") {
        const user = db.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").get(chatter.channel.replace("#", ""));
        let record = calculate_record(user.user_id);
        let message = user.record_text_chat.replace("%w", record.win).replace("%l", record.loss).replace("%d", record.draw);
        Bot.say(message , chatter.channel);
    }

});

Bot.on('error', (error) => {
    console.log("Bot ran into error: " + error)
});


function get_user_or_create(channel_id, username) {
    const user = db.prepare("SELECT * FROM users WHERE user_id = ?").get(channel_id);
    if (user === undefined) {
        console.debug("Creating user with username " + username);
        const user_token = crypto.randomBytes(25).toString('hex');
        const default_text = "W - L %w %l";
        const default_text_chat = "Record: W - L %w %l";
        const default_custom_css = "body {font-family: 'Roboto Condensed', sans-serif;}\n#text_content {color: white;text-shadow: -2px -2px 0 #000, 2px -2px 0 #000, -2px 2px 0 #000, 2px 2px 0 #000;}\n";
        const default_custom_html = "<link href='https://fonts.googleapis.com/css?family=Roboto+Condensed&display=swap' rel='stylesheet'>";

        db.prepare("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(channel_id, username, user_token, 1, 1, default_text, default_text_chat, default_custom_html, default_custom_css);

        Bot.join(username);
        twitchWebhook.subscribe('streams', {
            user_id: channel_id
        });
        return db.prepare("SELECT * FROM users WHERE user_id = ?").get(channel_id);
    }
    if (user.username !== username) {
        db.prepare("UPDATE users SET username = ? WHERE user_id = ?").run(username, channel_id);
        return db.prepare("SELECT * FROM users WHERE user_id = ?").get(channel_id);
    }
    return user
}

function init() {
    console.debug("Joining twitch chat for users");
    let chat_enabled_users = db.prepare("SELECT username FROM users WHERE enabled = 1").all();
    chat_enabled_users.forEach(function (user) {
        Bot.join(user.username);
    });


    console.debug("Subscribing to webhook for users");
    let auto_twitch_users = db.prepare("SELECT user_id FROM users WHERE record_reset = 1").all();
    auto_twitch_users.forEach(function (user) {
        twitchWebhook.subscribe('streams', {
            user_id: user.user_id
        });
    });

}


Bot.on('connected', () => {
    console.debug("Bot connected to twitch, starting connections");
    init();
});



app.get('/', function (req, res) {
    if (check_authorized(req)) {
        res.redirect("/manage")
    } else {
        res.render("landing")
    }
});

app.get('/manage', csrfProtection, function (req, res) {
    if (check_authorized(req)) {
        const user_id = req.session.passport.user.data[0].id;
        const username = req.session.passport.user.data[0].display_name;
        const user = get_user_or_create(user_id, username);
        let record = calculate_record(user.user_id);
        let message = user.record_text.replace("%w", record.win).replace("%l", record.loss).replace("%d", record.draw);
        res.render("main", {user: user, username: username, url: REGULAR_URL, record_message: message, record: record, csrfToken: req.csrfToken()});
    } else {
        res.redirect("/")
    }
});

app.get("/data", function (req, res) {
    if (check_authorized(req)) {
        const user_id = req.session.passport.user.data[0].id;
        const username = req.session.passport.user.data[0].display_name;
        const user = get_user_or_create(user_id, username);
        const user_events = db.prepare("SELECT * FROM events WHERE user_id = ?").all(user_id);
        res.json({user: user, events: user_events})
    }else{
        res.redirect("/")
    }
});


app.post("/regenerate_token", csrfProtection, function (req, res) {
    if (check_authorized(req)) {
        const user_token = crypto.randomBytes(25).toString('hex');
        db.prepare("UPDATE users SET token = ? WHERE user_id = ?").run(user_token, req.session.passport.user.data[0].id);
        res.redirect("/manage")

    }else{
        res.send("Something went wrong...")
    }
});

app.post("/delete_account", csrfProtection, function (req, res) {
    if (check_authorized(req)) {
        db.prepare("DELETE FROM users WHERE user_id = ?").run(req.session.passport.user.data[0].id);
        db.prepare("DELETE FROM events WHERE user_id = ?").run(req.session.passport.user.data[0].id);
        req.logout();
        res.send("Your account has been deleted!")
    }else{
        res.send("Something went wrong...")
    }
});


app.post("/change_settings", csrfProtection, function (req, res) {
    let enable = req.body.enable_twitch_bot === "on" ? 1 : 0;
    let auto_record = req.body.enable_auto_reset === "on" ? 1 : 0;
    let record_text = sanitizeHtml(req.body.record_text);
    let record_text_chat = sanitizeHtml(req.body.record_text_chat);
    let record_html = req.body.record_html;
    let record_css = req.body.record_css;
    let token = req.body.token;
    const statement = db.prepare("UPDATE users SET enabled = ?, record_reset = ?, record_text = ?, record_text_chat = ?, custom_html = ?, custom_css = ? WHERE token = ?");
    const updates = statement.run(enable, auto_record, record_text, record_text_chat, record_html, record_css, token);
    refresh_client(token);
    res.redirect("/manage/")
});

app.get('/embed/:token', function (req, res) {
    let user = db.prepare("SELECT * FROM users WHERE token = ?").get(req.params.token);
    if (user === undefined) {
        res.send("That URL doesn't look right...")
    }else{
        res.render("embed", {user: user, ws_url: WEBSOCKET_URL});
    }
});

app.post("/api", function (req, res) {
    let token = req.body.token;
    let action = req.body.action;
    let user = db.prepare("SELECT * FROM users WHERE token = ?").get(token);
    if (user === undefined) {
        res.json({error: true, "message": "incorrect token"})
    }else{
        if (action === "win") {
            record_win(user.username);
            res.json({success: true})
        }else if (action === "loss") {
            record_loss(user.username);
            res.json({success: true})
        }else if (action === "draw") {
            record_draw(user.username);
            res.json({success: true})
        }else if (action === "reset") {
            record_reset(user.username);
            res.json({success: true})
        }else if(action === "record") {
            let record = calculate_record(user.user_id);
            let message = user.record_text.replace("%w", record.win).replace("%l", record.loss).replace("%d", record.draw);
            res.json({success: true, record: record, record_message: message})
        }
        else{
            res.json({error: true, message: "unknown action"})
        }
    }

});

app.ws("/ws", function (ws, req) {
    ws.on("message", function (data) {
        if (data.startsWith("auth_request")) {
            let token = data.split(" ")[1];
            const user = db.prepare("SELECT * FROM users WHERE token = ?").get(token);
            if (user !== undefined) {
                ws.id = token;
                ws.send("auth_ok")
            }else{
                ws.send("auth_error")
            }
        }else if (data === "get_message") {
            if (ws.id !== undefined) {
                const user = db.prepare("SELECT * FROM users WHERE token = ?").get(ws.id);
                let record = calculate_record(user.user_id);
                let message = user.record_text.replace("%w", record.win).replace("%l", record.loss).replace("%d", record.draw);
                ws.send("record_payload " + message);
            }else{
                ws.send("no_auth_error")
            }
        }else if (data.startsWith("subscribe")){
            ws.is_subscribed = !!data.split(" ")[1];
            ws.send("subscribe_change_ok")
        }else if (data === "hbc") {
            ws.send("hbs")
        }else{
            ws.send("unknown_command_error")
        }
    });
});

app.listen(WEB_PORT, () => console.log(`RecordBot listening on port ${WEB_PORT}!`));