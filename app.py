import os
import secrets
import json
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
CORS(app)

DB_PATH = os.environ.get('DB_PATH', '/tmp/shopping.db')

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
        CREATE TABLE IF NOT EXISTS households (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
    ''')
    db.commit()
    db.close()

init_db()

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Household-Token') or request.args.get('token')
        if not token:
            return jsonify({'error': 'token required'}), 401
        db = get_db()
        hh = db.execute('SELECT * FROM households WHERE token=?', (token,)).fetchone()
        if not hh:
            return jsonify({'error': 'invalid token'}), 401
        g.household_id = hh['id']
        return f(*args, **kwargs)
    return decorated

@app.route('/health')
def health():
    return jsonify({'ok': True, 'time': datetime.utcnow().isoformat()})

# ── Household ─────────────────────────────────────────────

@app.route('/household', methods=['POST'])
def create_household():
    token = secrets.token_urlsafe(16)
    db = get_db()
    db.execute('INSERT INTO households (token) VALUES (?)', (token,))
    db.commit()
    return jsonify({'token': token}), 201

# ── Shopping List ──────────────────────────────────────────

@app.route('/list', methods=['GET'])
@require_token
def get_list():
    db = get_db()
    rows = db.execute(
        'SELECT * FROM list_items WHERE household_id=? ORDER BY created_at',
        (g.household_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/list', methods=['POST'])
@require_token
def add_list_item():
    data = request.get_json()
    item_id = data.get('id') or secrets.token_hex(8)
    db = get_db()
    now = datetime.utcnow().isoformat()
    db.execute('''
        INSERT OR REPLACE INTO list_items
        (id, household_id, name, store, price, category, quantity, checked, item_id, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        item_id, g.household_id,
        data.get('name', ''),
        data.get('store'),
        data.get('price'),
        data.get('category', 'その他'),
        data.get('quantity', 1),
        1 if data.get('checked') else 0,
        data.get('itemId') or data.get('item_id'),
        data.get('created_at', now),
        now
    ))
    db.commit()
    return jsonify({'id': item_id}), 201

@app.route('/list/<item_id>', methods=['PATCH'])
@require_token
def update_list_item(item_id):
    data = request.get_json()
    db = get_db()
    row = db.execute('SELECT * FROM list_items WHERE id=? AND household_id=?',
                     (item_id, g.household_id)).fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404
    fields = {k: v for k, v in data.items() if k in ('name', 'store', 'price', 'category', 'quantity', 'checked', 'item_id')}
    if 'checked' in fields:
        fields['checked'] = 1 if fields['checked'] else 0
    fields['updated_at'] = datetime.utcnow().isoformat()
    sets = ', '.join(f'{k}=?' for k in fields)
    db.execute(f'UPDATE list_items SET {sets} WHERE id=? AND household_id=?',
               list(fields.values()) + [item_id, g.household_id])
    db.commit()
    return jsonify({'ok': True})

@app.route('/list/<item_id>', methods=['DELETE'])
@require_token
def delete_list_item(item_id):
    db = get_db()
    db.execute('DELETE FROM list_items WHERE id=? AND household_id=?', (item_id, g.household_id))
    db.commit()
    return jsonify({'ok': True})

@app.route('/list/sync', methods=['POST'])
@require_token
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

@app.route('/items', methods=['GET'])
@require_token
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

@app.route('/items', methods=['POST'])
@require_token
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

@app.route('/items/sync', methods=['POST'])
@require_token
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

# ── Alexa Handler ──────────────────────────────────────────

@app.route('/alexa', methods=['POST'])
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
            return speak(f'リストには{len(names)}件あります。{「、」.join(names[:5])}{"など" if len(names) > 5 else ""}です。')

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)), debug=False)
