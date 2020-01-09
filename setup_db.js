const Database = require('better-sqlite3');
const db = new Database('main.db');
db.prepare("DROP TABLE IF EXISTS users").run();
db.prepare("DROP TABLE IF EXISTS events").run();
db.prepare("CREATE TABLE users (user_id INTEGER UNIQUE, username TEXT UNIQUE, token TEXT UNIQUE, enabled INTEGER, record_reset INTEGER, record_text TEXT, record_text_chat TEXT, custom_html TEXT, custom_css TEXT)").run();
db.prepare("CREATE TABLE events (user_id INTEGER, type TEXT, time NUMERIC)").run();
