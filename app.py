import os
import secrets
import json
import hashlib
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='dist', static_url_path='')
CORS(app)

DB_PATH = os.environ.get('DB_PATH', '/tmp/shopping.db')
HOUSEHOLD_ID = 1  # 全員が同じ世帯を共有

def hash_pin(pin):
    return hashlib.sha256(pin.encode()).hexdigest()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pin_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS list_items (
            id TEXT PRIMARY KEY,
            household_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            store TEXT,
            price REAL,
            category TEXT,
            quantity INTEGER DEFAULT 1,
            checked INTEGER DEFAULT 0,
            item_id TEXT,
            note TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS regular_items (
            id TEXT PRIMARY KEY,
            household_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            store TEXT,
            price REAL,
            category TEXT,
            cycle_days INTEGER,
            last_bought_at TEXT,
            purchase_history TEXT DEFAULT '[]',
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS finance (
            id TEXT PRIMARY KEY,
            household_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            category TEXT,
            name TEXT,
            store TEXT,
            amount REAL NOT NULL,
            date TEXT,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS stores (
            id TEXT PRIMARY KEY,
            household_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            category TEXT,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS budgets (
            household_id INTEGER PRIMARY KEY,
            monthly REAL DEFAULT 0,
            categories TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS list_history (
            household_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            store TEXT,
            price REAL,
            category TEXT,
            PRIMARY KEY (household_id, name)
        );
        CREATE TABLE IF NOT EXISTS recurring (
            id TEXT PRIMARY KEY,
            household_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            category TEXT,
            day_of_month INTEGER DEFAULT 1,
            interval_months INTEGER DEFAULT 1,
            start_month INTEGER DEFAULT 1,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS item_store_prices (
            id TEXT PRIMARY KEY,
            item_id TEXT NOT NULL,
            household_id INTEGER NOT NULL,
            store_name TEXT NOT NULL,
            price REAL NOT NULL,
            unit_size REAL,
            unit_type TEXT DEFAULT '個',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    db.commit()
    db.close()

init_db()

# 既存DBへのカラム追加マイグレーション
def migrate_db():
    db = sqlite3.connect(DB_PATH)
    for col_sql in [
        'ALTER TABLE list_items ADD COLUMN note TEXT DEFAULT ""',
        'ALTER TABLE recurring ADD COLUMN interval_months INTEGER DEFAULT 1',
        'ALTER TABLE recurring ADD COLUMN start_month INTEGER DEFAULT 1',
    ]:
        try:
            db.execute(col_sql)
            db.commit()
        except Exception:
            pass
    try:
        db.execute('''CREATE TABLE IF NOT EXISTS item_store_prices (
            id TEXT PRIMARY KEY, item_id TEXT NOT NULL, household_id INTEGER NOT NULL,
            store_name TEXT NOT NULL, price REAL NOT NULL, unit_size REAL,
            unit_type TEXT DEFAULT "個", updated_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
        db.commit()
    except Exception:
        pass
    db.close()

migrate_db()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'unauthorized'}), 401
        db = get_db()
        now = datetime.utcnow().isoformat()
        row = db.execute(
            'SELECT * FROM sessions WHERE token=? AND expires_at>?', (token, now)
        ).fetchone()
        if not row:
            return jsonify({'error': 'unauthorized'}), 401
        g.household_id = HOUSEHOLD_ID
        g.user_id = row['user_id']
        return f(*args, **kwargs)
    return decorated

@app.route('/api/health')
def health():
    return jsonify({'ok': True, 'time': datetime.utcnow().isoformat()})

# ── Auth ──────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    pin = str(data.get('pin') or '')
    if not username or len(pin) != 4 or not pin.isdigit():
        return jsonify({'error': 'ユーザー名と4桁のPINが必要です'}), 400
    db = get_db()
    if db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
        return jsonify({'error': 'そのユーザー名は使われています'}), 409
    db.execute('INSERT INTO users (username, pin_hash) VALUES (?,?)', (username, hash_pin(pin)))
    db.commit()
    return jsonify({'ok': True}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = (data.get('username') or '').strip()
    pin = str(data.get('pin') or '')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not user or user['pin_hash'] != hash_pin(pin):
        return jsonify({'error': 'ユーザー名またはPINが違います'}), 401
    token = secrets.token_urlsafe(32)
    expires = (datetime.utcnow() + timedelta(days=365)).isoformat()
    db.execute('INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)',
               (token, user['id'], expires))
    db.commit()
    return jsonify({'token': token, 'username': user['username']})

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    db = get_db()
    user = db.execute('SELECT username FROM users WHERE id=?', (g.user_id,)).fetchone()
    return jsonify({'username': user['username'] if user else ''})

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    get_db().execute('DELETE FROM sessions WHERE token=?', (token,))
    get_db().commit()
    return jsonify({'ok': True})

@app.route('/api/auth/me', methods=['PATCH'])
@require_auth
def update_me():
    data = request.get_json()
    db = get_db()
    new_username = (data.get('username') or '').strip()
    new_pin = str(data.get('pin') or '')
    if new_username:
        exists = db.execute('SELECT id FROM users WHERE username=? AND id!=?', (new_username, g.user_id)).fetchone()
        if exists:
            return jsonify({'error': 'そのユーザー名は使われています'}), 409
        db.execute('UPDATE users SET username=? WHERE id=?', (new_username, g.user_id))
    if new_pin:
        if len(new_pin) != 4 or not new_pin.isdigit():
            return jsonify({'error': 'PINは4桁の数字にしてください'}), 400
        db.execute('UPDATE users SET pin_hash=? WHERE id=?', (hash_pin(new_pin), g.user_id))
    db.commit()
    user = db.execute('SELECT username FROM users WHERE id=?', (g.user_id,)).fetchone()
    return jsonify({'username': user['username']})

@app.route('/api/users', methods=['GET'])
def list_users():
    """ユーザーが存在するか確認（初回登録画面の判定用）"""
    db = get_db()
    count = db.execute('SELECT COUNT(*) as c FROM users').fetchone()['c']
    return jsonify({'count': count})

# ── Shopping List ──────────────────────────────────────────

@app.route('/api/list', methods=['GET'])
@require_auth
def get_list():
    db = get_db()
    rows = db.execute(
        'SELECT * FROM list_items WHERE household_id=? ORDER BY created_at',
        (g.household_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/list', methods=['POST'])
@require_auth
def add_list_item():
    data = request.get_json()
    item_id = data.get('id') or secrets.token_hex(8)
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute('''
        INSERT OR REPLACE INTO list_items
        (id, household_id, name, store, price, category, quantity, checked, item_id, note, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        item_id, g.household_id,
        data.get('name', ''),
        data.get('store'),
        data.get('price'),
        data.get('category', 'その他'),
        data.get('quantity', 1),
        1 if data.get('checked') else 0,
        data.get('itemId') or data.get('item_id'),
        data.get('note', ''),
        data.get('created_at', now),
        now
    ))
    db.commit()
    return jsonify({'id': item_id}), 201

@app.route('/api/list/<item_id>', methods=['PATCH'])
@require_auth
def update_list_item(item_id):
    data = request.get_json()
    db = get_db()
    row = db.execute('SELECT * FROM list_items WHERE id=? AND household_id=?',
                     (item_id, g.household_id)).fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404
    fields = {k: v for k, v in data.items() if k in ('name', 'store', 'price', 'category', 'quantity', 'checked', 'item_id', 'note')}
    if 'checked' in fields:
        fields['checked'] = 1 if fields['checked'] else 0
    fields['updated_at'] = datetime.utcnow().isoformat()
    sets = ', '.join(f'{k}=?' for k in fields)
    db.execute(f'UPDATE list_items SET {sets} WHERE id=? AND household_id=?',
               list(fields.values()) + [item_id, g.household_id])
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/list/<item_id>', methods=['DELETE'])
@require_auth
def delete_list_item(item_id):
    db = get_db()
    db.execute('DELETE FROM list_items WHERE id=? AND household_id=?', (item_id, g.household_id))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/list/sync', methods=['POST'])
@require_auth
def sync_list():
    """Bulk sync from client: replaces all unchecked items."""
    data = request.get_json()
    items = data.get('items', [])
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute('DELETE FROM list_items WHERE household_id=? AND checked=0', (g.household_id,))
    for item in items:
        if item.get('checked'):
            continue
        db.execute('''
            INSERT OR REPLACE INTO list_items
            (id, household_id, name, store, price, category, quantity, checked, item_id, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            item.get('id') or secrets.token_hex(8),
            g.household_id,
            item.get('name', ''),
            item.get('store'),
            item.get('price'),
            item.get('category', 'その他'),
            item.get('quantity', 1),
            0,
            item.get('itemId') or item.get('item_id'),
            item.get('created_at', now),
            now
        ))
    db.commit()
    return jsonify({'ok': True, 'synced': len(items)})

# ── Regular Items ──────────────────────────────────────────

@app.route('/api/items', methods=['GET'])
@require_auth
def get_items():
    db = get_db()
    rows = db.execute(
        'SELECT * FROM regular_items WHERE household_id=? ORDER BY created_at',
        (g.household_id,)
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        try:
            d['purchase_history'] = json.loads(d['purchase_history'] or '[]')
        except Exception:
            d['purchase_history'] = []
        result.append(d)
    return jsonify(result)

@app.route('/api/items', methods=['POST'])
@require_auth
def add_item():
    data = request.get_json()
    item_id = data.get('id') or secrets.token_hex(8)
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute('''
        INSERT OR REPLACE INTO regular_items
        (id, household_id, name, store, price, category, cycle_days, last_bought_at, purchase_history, notes, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        item_id, g.household_id,
        data.get('name', ''),
        data.get('store'),
        data.get('price'),
        data.get('category', 'その他'),
        data.get('cycleDays') or data.get('cycle_days'),
        data.get('lastBoughtAt') or data.get('last_bought_at'),
        json.dumps(data.get('purchaseHistory') or data.get('purchase_history') or []),
        data.get('notes'),
        data.get('createdAt') or now,
        now
    ))
    db.commit()
    return jsonify({'id': item_id}), 201

@app.route('/api/items/sync', methods=['POST'])
@require_auth
def sync_items():
    """Bulk sync regular items from client."""
    data = request.get_json()
    items = data.get('items', [])
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute('DELETE FROM regular_items WHERE household_id=?', (g.household_id,))
    for item in items:
        db.execute('''
            INSERT OR REPLACE INTO regular_items
            (id, household_id, name, store, price, category, cycle_days, last_bought_at, purchase_history, notes, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            item.get('id') or secrets.token_hex(8),
            g.household_id,
            item.get('name', ''),
            item.get('store'),
            item.get('price'),
            item.get('category', 'その他'),
            item.get('cycleDays') or item.get('cycle_days'),
            item.get('lastBoughtAt') or item.get('last_bought_at'),
            json.dumps(item.get('purchaseHistory') or item.get('purchase_history') or []),
            item.get('notes'),
            item.get('createdAt') or now,
            now
        ))
    db.commit()
    return jsonify({'ok': True, 'synced': len(items)})

# ── Item Store Prices ──────────────────────────────────────

@app.route('/api/item-prices', methods=['GET'])
@require_auth
def get_item_prices():
    db = get_db()
    rows = db.execute(
        'SELECT * FROM item_store_prices WHERE household_id=? ORDER BY item_id, price',
        (g.household_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/item-prices', methods=['POST'])
@require_auth
def add_item_price():
    data = request.get_json()
    pid = data.get('id') or secrets.token_hex(8)
    now = datetime.utcnow().isoformat()
    db = get_db()
    db.execute('''INSERT OR REPLACE INTO item_store_prices
                  (id, item_id, household_id, store_name, price, unit_size, unit_type, updated_at)
                  VALUES (?,?,?,?,?,?,?,?)''',
               (pid, data.get('item_id', ''), g.household_id,
                data.get('store_name', ''), data.get('price', 0),
                data.get('unit_size') or None, data.get('unit_type', '個'), now))
    db.commit()
    return jsonify({'id': pid}), 201

@app.route('/api/item-prices/<pid>', methods=['PATCH'])
@require_auth
def update_item_price(pid):
    data = request.get_json()
    fields = {k: v for k, v in data.items() if k in ('store_name', 'price', 'unit_size', 'unit_type')}
    if not fields:
        return jsonify({'error': 'no fields'}), 400
    fields['updated_at'] = datetime.utcnow().isoformat()
    db = get_db()
    set_clause = ', '.join(f'{k}=?' for k in fields)
    db.execute(f'UPDATE item_store_prices SET {set_clause} WHERE id=? AND household_id=?',
               list(fields.values()) + [pid, g.household_id])
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/item-prices/<pid>', methods=['DELETE'])
@require_auth
def delete_item_price(pid):
    db = get_db()
    db.execute('DELETE FROM item_store_prices WHERE id=? AND household_id=?', (pid, g.household_id))
    db.commit()
    return jsonify({'ok': True})

# ── Alexa Handler ──────────────────────────────────────────

@app.route('/api/alexa', methods=['POST'])
def alexa_handler():
    """Alexa Skills Kit endpoint."""
    body = request.get_json(force=True)
    request_type = body.get('request', {}).get('type')
    session_attrs = body.get('session', {}).get('attributes', {})

    def speak(text, end=True):
        return jsonify({
            'version': '1.0',
            'sessionAttributes': session_attrs,
            'response': {
                'outputSpeech': {'type': 'PlainText', 'text': text},
                'shouldEndSession': end
            }
        })

    if request_type == 'LaunchRequest':
        return speak('かいもの帳へようこそ。買い物リストに追加したい商品名を言ってください。', end=False)

    if request_type == 'IntentRequest':
        intent = body['request']['intent']['name']
        slots = body['request']['intent'].get('slots', {})

        token = body.get('session', {}).get('user', {}).get('accessToken')
        if not token and intent not in ('AMAZON.HelpIntent', 'AMAZON.CancelIntent', 'AMAZON.StopIntent'):
            return speak('アカウントのリンクが必要です。Alexaアプリでかいもの帳のアカウントを連携してください。')

        db_conn = sqlite3.connect(DB_PATH)
        db_conn.row_factory = sqlite3.Row

        def get_household():
            return db_conn.execute('SELECT * FROM households WHERE token=?', (token,)).fetchone()

        if intent == 'AddItemIntent':
            item_name = slots.get('ItemName', {}).get('value', '')
            if not item_name:
                return speak('商品名が聞き取れませんでした。もう一度お試しください。', end=False)
            hh = get_household()
            if not hh:
                db_conn.close()
                return speak('アカウントが見つかりません。アプリから再度連携してください。')
            item_id = secrets.token_hex(8)
            now = datetime.utcnow().isoformat()
            db_conn.execute('''
                INSERT INTO list_items (id, household_id, name, category, quantity, checked, created_at, updated_at)
                VALUES (?,?,?,?,1,0,?,?)
            ''', (item_id, hh['id'], item_name, 'その他', now, now))
            db_conn.commit()
            db_conn.close()
            return speak(f'{item_name}を買い物リストに追加しました。')

        elif intent == 'ListItemsIntent':
            hh = get_household()
            if not hh:
                db_conn.close()
                return speak('アカウントが見つかりません。')
            rows = db_conn.execute(
                'SELECT name FROM list_items WHERE household_id=? AND checked=0 ORDER BY created_at',
                (hh['id'],)
            ).fetchall()
            db_conn.close()
            if not rows:
                return speak('買い物リストは空です。')
            names = [r['name'] for r in rows]
            if len(names) == 1:
                return speak(f'リストには{names[0]}があります。')
            listing = '、'.join(names[:5]) + ('など' if len(names) > 5 else '')
            return speak(f'リストには{len(names)}件あります。{listing}です。')

        elif intent == 'CheckStockIntent':
            hh = get_household()
            if not hh:
                db_conn.close()
                return speak('アカウントが見つかりません。')
            rows = db_conn.execute(
                'SELECT name, cycle_days, last_bought_at, price FROM regular_items WHERE household_id=?',
                (hh['id'],)
            ).fetchall()
            db_conn.close()
            now = datetime.utcnow()
            due = []
            for r in rows:
                if not r['cycle_days'] or not r['last_bought_at']:
                    continue
                last = datetime.fromisoformat(r['last_bought_at'].replace('Z', ''))
                next_buy = last + timedelta(days=r['cycle_days'])
                days_until = (next_buy - now).days
                if days_until <= 3:
                    due.append((r['name'], days_until))
            if not due:
                return speak('今週買う必要があるものはなさそうです。')
            items_text = '、'.join(f'{n}{"は今日頃" if d <= 0 else f"はあと{d}日で"}なくなりそうです' for n, d in due[:3])
            return speak(items_text)

        db_conn.close()

    if request_type == 'SessionEndedRequest':
        return jsonify({'version': '1.0', 'response': {}})

    return jsonify({'version': '1.0', 'response': {
        'outputSpeech': {'type': 'PlainText', 'text': 'すみません、もう一度お試しください。'},
        'shouldEndSession': True
    }})

# ── Finance ───────────────────────────────────────────────

@app.route('/api/finance', methods=['GET'])
@require_auth
def get_finance():
    db = get_db()
    rows = db.execute('SELECT * FROM finance WHERE household_id=? ORDER BY date DESC', (g.household_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/finance', methods=['POST'])
@require_auth
def add_finance():
    data = request.get_json()
    fid = data.get('id') or secrets.token_hex(8)
    db = get_db()
    db.execute('''INSERT OR REPLACE INTO finance (id,household_id,type,category,name,store,amount,date,note)
                  VALUES (?,?,?,?,?,?,?,?,?)''',
               (fid, g.household_id, data.get('type','expense'), data.get('category'),
                data.get('name'), data.get('store'), data.get('amount',0),
                data.get('date'), data.get('note')))
    db.commit()
    return jsonify({'id': fid}), 201

@app.route('/api/finance/<fid>', methods=['PATCH'])
@require_auth
def update_finance(fid):
    data = request.get_json()
    db = get_db()
    fields = {k: data[k] for k in ('type','category','name','store','amount','date','note') if k in data}
    if fields:
        sets = ', '.join(f'{k}=?' for k in fields)
        db.execute(f'UPDATE finance SET {sets} WHERE id=? AND household_id=?',
                   list(fields.values()) + [fid, g.household_id])
        db.commit()
    return jsonify({'ok': True})

@app.route('/api/finance/<fid>', methods=['DELETE'])
@require_auth
def delete_finance(fid):
    db = get_db()
    db.execute('DELETE FROM finance WHERE id=? AND household_id=?', (fid, g.household_id))
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/finance/sync', methods=['POST'])
@require_auth
def sync_finance():
    data = request.get_json()
    records = data.get('records', [])
    db = get_db()
    db.execute('DELETE FROM finance WHERE household_id=?', (g.household_id,))
    for r in records:
        db.execute('''INSERT OR REPLACE INTO finance (id,household_id,type,category,name,store,amount,date,note)
                      VALUES (?,?,?,?,?,?,?,?,?)''',
                   (r.get('id') or secrets.token_hex(8), g.household_id, r.get('type','expense'),
                    r.get('category'), r.get('name'), r.get('store'), r.get('amount',0),
                    r.get('date'), r.get('note')))
    db.commit()
    return jsonify({'ok': True})

# ── Stores ────────────────────────────────────────────────

@app.route('/api/stores', methods=['GET'])
@require_auth
def get_stores():
    db = get_db()
    rows = db.execute('SELECT * FROM stores WHERE household_id=? ORDER BY created_at', (g.household_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/stores', methods=['POST'])
@require_auth
def add_store():
    data = request.get_json()
    sid = data.get('id') or secrets.token_hex(8)
    db = get_db()
    db.execute('INSERT OR REPLACE INTO stores (id,household_id,name,category,note) VALUES (?,?,?,?,?)',
               (sid, g.household_id, data.get('name',''), data.get('category'), data.get('note')))
    db.commit()
    return jsonify({'id': sid}), 201

@app.route('/api/stores/<sid>', methods=['PATCH'])
@require_auth
def update_store(sid):
    data = request.get_json()
    fields = {k: v for k, v in data.items() if k in ('name', 'category', 'note')}
    if not fields:
        return jsonify({'error': 'no fields'}), 400
    db = get_db()
    set_clause = ', '.join(f'{k}=?' for k in fields)
    db.execute(f'UPDATE stores SET {set_clause} WHERE id=? AND household_id=?',
               list(fields.values()) + [sid, g.household_id])
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/stores/<sid>', methods=['DELETE'])
@require_auth
def delete_store(sid):
    db = get_db()
    db.execute('DELETE FROM stores WHERE id=? AND household_id=?', (sid, g.household_id))
    db.commit()
    return jsonify({'ok': True})

# ── Budgets ───────────────────────────────────────────────

@app.route('/api/budgets', methods=['GET'])
@require_auth
def get_budgets():
    db = get_db()
    row = db.execute('SELECT * FROM budgets WHERE household_id=?', (g.household_id,)).fetchone()
    if not row:
        return jsonify({'monthly': 0, 'categories': {}})
    d = dict(row)
    try:
        d['categories'] = json.loads(d['categories'] or '{}')
    except Exception:
        d['categories'] = {}
    return jsonify(d)

@app.route('/api/budgets', methods=['PUT'])
@require_auth
def set_budgets():
    data = request.get_json()
    db = get_db()
    db.execute('INSERT OR REPLACE INTO budgets (household_id,monthly,categories) VALUES (?,?,?)',
               (g.household_id, data.get('monthly', 0), json.dumps(data.get('categories', {}))))
    db.commit()
    return jsonify({'ok': True})

# ── List History ──────────────────────────────────────────

@app.route('/api/list-history', methods=['GET'])
@require_auth
def get_list_history():
    db = get_db()
    rows = db.execute('SELECT * FROM list_history WHERE household_id=?', (g.household_id,)).fetchall()
    return jsonify({r['name']: {'store': r['store'], 'price': r['price'], 'category': r['category']} for r in rows})

@app.route('/api/list-history', methods=['POST'])
@require_auth
def upsert_list_history():
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({'error': 'name required'}), 400
    db = get_db()
    db.execute('INSERT OR REPLACE INTO list_history (household_id,name,store,price,category) VALUES (?,?,?,?,?)',
               (g.household_id, name, data.get('store'), data.get('price'), data.get('category')))
    db.commit()
    return jsonify({'ok': True})


# ── Recurring ────────────────────────────────────────────

@app.route('/api/recurring', methods=['GET'])
@require_auth
def get_recurring():
    db = get_db()
    rows = db.execute('SELECT * FROM recurring WHERE household_id=? ORDER BY day_of_month, name',
                      (g.household_id,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/recurring', methods=['POST'])
@require_auth
def add_recurring():
    data = request.get_json()
    rid = data.get('id') or secrets.token_hex(8)
    db = get_db()
    db.execute('''INSERT OR REPLACE INTO recurring
                  (id,household_id,name,type,amount,category,day_of_month,interval_months,start_month,active)
                  VALUES (?,?,?,?,?,?,?,?,?,?)''',
               (rid, g.household_id, data.get('name',''), data.get('type','expense'),
                data.get('amount',0), data.get('category','その他'),
                data.get('day_of_month',1),
                data.get('interval_months',1), data.get('start_month',1),
                1 if data.get('active', True) else 0))
    db.commit()
    return jsonify({'id': rid}), 201

@app.route('/api/recurring/<rid>', methods=['PATCH'])
@require_auth
def update_recurring(rid):
    data = request.get_json()
    fields = {k: v for k, v in data.items() if k in ('name','type','amount','category','day_of_month','interval_months','start_month','active')}
    if not fields:
        return jsonify({'error': 'no fields'}), 400
    db = get_db()
    set_clause = ', '.join(f'{k}=?' for k in fields)
    db.execute(f'UPDATE recurring SET {set_clause} WHERE id=? AND household_id=?',
               list(fields.values()) + [rid, g.household_id])
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/recurring/<rid>', methods=['DELETE'])
@require_auth
def delete_recurring(rid):
    db = get_db()
    db.execute('DELETE FROM recurring WHERE id=? AND household_id=?', (rid, g.household_id))
    db.commit()
    return jsonify({'ok': True})

# ── Backup / Restore ─────────────────────────────────────

@app.route('/api/backup', methods=['GET'])
@require_auth
def backup():
    db = get_db()
    hid = g.household_id
    rows_items = db.execute('SELECT * FROM regular_items WHERE household_id=?', (hid,)).fetchall()
    items_data = []
    for r in rows_items:
        d = dict(r)
        try: d['purchase_history'] = json.loads(d['purchase_history'] or '[]')
        except: d['purchase_history'] = []
        items_data.append(d)
    rows_list    = db.execute('SELECT * FROM list_items WHERE household_id=?', (hid,)).fetchall()
    rows_fin     = db.execute('SELECT * FROM finance WHERE household_id=? ORDER BY date', (hid,)).fetchall()
    rows_st      = db.execute('SELECT * FROM stores WHERE household_id=?', (hid,)).fetchall()
    row_bud      = db.execute('SELECT * FROM budgets WHERE household_id=?', (hid,)).fetchone()
    rows_hist    = db.execute('SELECT * FROM list_history WHERE household_id=?', (hid,)).fetchall()
    rows_rec     = db.execute('SELECT * FROM recurring WHERE household_id=?', (hid,)).fetchall()
    rows_iprices = db.execute('SELECT * FROM item_store_prices WHERE household_id=?', (hid,)).fetchall()
    bud = {'monthly': 0, 'categories': {}}
    if row_bud:
        bd = dict(row_bud)
        try: bd['categories'] = json.loads(bd.get('categories') or '{}')
        except: bd['categories'] = {}
        bud = bd
    return jsonify({
        'version': '1.1',
        'exported_at': datetime.utcnow().isoformat(),
        'items': items_data,
        'list': [dict(r) for r in rows_list],
        'finance': [dict(r) for r in rows_fin],
        'stores': [dict(r) for r in rows_st],
        'budgets': bud,
        'list_history': {r['name']: {'store': r['store'], 'price': r['price'], 'category': r['category']} for r in rows_hist},
        'recurring': [dict(r) for r in rows_rec],
        'item_store_prices': [dict(r) for r in rows_iprices],
    })

@app.route('/api/restore', methods=['POST'])
@require_auth
def restore():
    data = request.get_json()
    if not data or data.get('version') not in ('1.0', '1.1'):
        return jsonify({'error': '無効なバックアップファイルです'}), 400
    db = get_db()
    hid = g.household_id
    now = datetime.utcnow().isoformat()
    db.execute('DELETE FROM regular_items WHERE household_id=?', (hid,))
    db.execute('DELETE FROM list_items WHERE household_id=?', (hid,))
    db.execute('DELETE FROM finance WHERE household_id=?', (hid,))
    db.execute('DELETE FROM stores WHERE household_id=?', (hid,))
    db.execute('DELETE FROM budgets WHERE household_id=?', (hid,))
    db.execute('DELETE FROM list_history WHERE household_id=?', (hid,))
    db.execute('DELETE FROM recurring WHERE household_id=?', (hid,))
    db.execute('DELETE FROM item_store_prices WHERE household_id=?', (hid,))
    for item in data.get('items', []):
        db.execute('''INSERT OR REPLACE INTO regular_items
            (id,household_id,name,store,price,category,cycle_days,last_bought_at,purchase_history,notes,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (item.get('id') or secrets.token_hex(8), hid,
             item.get('name',''), item.get('store'), item.get('price'),
             item.get('category'), item.get('cycle_days'), item.get('last_bought_at'),
             json.dumps(item.get('purchase_history') or []),
             item.get('notes'), item.get('created_at', now), now))
    for li in data.get('list', []):
        db.execute('''INSERT OR REPLACE INTO list_items
            (id,household_id,name,store,price,category,quantity,checked,item_id,note,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
            (li.get('id') or secrets.token_hex(8), hid,
             li.get('name',''), li.get('store'), li.get('price'),
             li.get('category','その他'), li.get('quantity',1),
             1 if li.get('checked') else 0,
             li.get('item_id') or li.get('itemId'),
             li.get('note',''), li.get('created_at', now), now))
    for f in data.get('finance', []):
        db.execute('''INSERT OR REPLACE INTO finance (id,household_id,type,category,name,store,amount,date,note)
                      VALUES (?,?,?,?,?,?,?,?,?)''',
                   (f.get('id') or secrets.token_hex(8), hid,
                    f.get('type','expense'), f.get('category'),
                    f.get('name'), f.get('store'), f.get('amount',0),
                    f.get('date'), f.get('note')))
    for s in data.get('stores', []):
        db.execute('INSERT OR REPLACE INTO stores (id,household_id,name,category,note) VALUES (?,?,?,?,?)',
                   (s.get('id') or secrets.token_hex(8), hid,
                    s.get('name',''), s.get('category'), s.get('note')))
    bud = data.get('budgets', {})
    db.execute('INSERT OR REPLACE INTO budgets (household_id,monthly,categories) VALUES (?,?,?)',
               (hid, bud.get('monthly',0), json.dumps(bud.get('categories',{}))))
    for name, hist in data.get('list_history', {}).items():
        db.execute('INSERT OR REPLACE INTO list_history (household_id,name,store,price,category) VALUES (?,?,?,?,?)',
                   (hid, name, hist.get('store'), hist.get('price'), hist.get('category')))
    for r in data.get('recurring', []):
        db.execute('''INSERT OR REPLACE INTO recurring (id,household_id,name,type,amount,category,day_of_month,interval_months,start_month,active)
                      VALUES (?,?,?,?,?,?,?,?,?,?)''',
                   (r.get('id') or secrets.token_hex(8), hid,
                    r.get('name',''), r.get('type','expense'),
                    r.get('amount',0), r.get('category'),
                    r.get('day_of_month',1), r.get('interval_months',1), r.get('start_month',1),
                    1 if r.get('active',True) else 0))
    for ip in data.get('item_store_prices', []):
        db.execute('''INSERT OR REPLACE INTO item_store_prices
                      (id, item_id, household_id, store_name, price, unit_size, unit_type, updated_at)
                      VALUES (?,?,?,?,?,?,?,?)''',
                   (ip.get('id') or secrets.token_hex(8), ip.get('item_id',''), hid,
                    ip.get('store_name',''), ip.get('price',0),
                    ip.get('unit_size'), ip.get('unit_type','個'),
                    ip.get('updated_at', now)))
    db.commit()
    return jsonify({'ok': True})

# ── React SPA ─────────────────────────────────────────────

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')
