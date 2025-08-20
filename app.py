import sqlite3
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # change this to a strong secret

# ----- Calculator logic -----
SAFARICOM_FEES = [
    (1, 100, 0),
    (101, 500, 11),
    (501, 1000, 27),
    (1001, 3500, 27),
    (3501, 10000, 44),
    (10001, 25000, 54),
    (25001, 50000, 70),
    (50001, 100000, 105),
    (100001, 500000, 110)
]

COMPETITOR_FEE_KWD = 1.25
DISTRIBUTOR_FEE_KWD = 0.4
BASE_PROFIT_KWD = 0.1
MAX_MARGIN_KWD = 1.1
MIN_TXN_KWD = 5.0
MAX_TXN_KWD = 600.0

def get_safaricom_fee(amount_kes):
    for low, high, fee in SAFARICOM_FEES:
        if low <= amount_kes <= high:
            return fee
    return 0

def calculate_base_margin(saf_fee_kwd, distributor_fee_kwd, base_profit=BASE_PROFIT_KWD):
    return saf_fee_kwd + distributor_fee_kwd + base_profit

def calculate_dynamic_margin(amount_kwd, saf_fee_kwd, distributor_fee_kwd):
    base_margin = calculate_base_margin(saf_fee_kwd, distributor_fee_kwd)
    if amount_kwd <= 50:
        margin = base_margin
    else:
        max_extra_margin = MAX_MARGIN_KWD - base_margin
        if max_extra_margin < 0:
            max_extra_margin = 0
        extra_amount = amount_kwd - 50
        extra_margin = min(max_extra_margin, 0.01 * extra_amount)
        margin = base_margin + extra_margin
    margin = min(margin, MAX_MARGIN_KWD)
    return margin

def clamp_amount(amount):
    if amount < MIN_TXN_KWD:
        return MIN_TXN_KWD, f"Minimum transaction is {MIN_TXN_KWD:.0f} KWD. Value adjusted."
    elif amount > MAX_TXN_KWD:
        return MAX_TXN_KWD, f"Maximum transaction is {MAX_TXN_KWD:.0f} KWD. Value adjusted."
    else:
        return amount, None

# ----- Authentication -----
users = {
    "eugenekirubi@gmail.com": generate_password_hash("adminpassword")
}

CUSTOMER_EMAIL = 'kirubieugene@gmail.com'
CUSTOMER_PASSWORD = 'secret123'
MERCHANT_EMAIL = 'merchant@example.com'
MERCHANT_PASSWORD = 'merchant123'

customers = {CUSTOMER_EMAIL: generate_password_hash(CUSTOMER_PASSWORD)}
merchants = {MERCHANT_EMAIL: generate_password_hash(MERCHANT_PASSWORD)}

# ----- Database -----
DATABASE = "logs.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # Create transactions table if not exists
        db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                amount_kwd REAL,
                amount_kes REAL,
                profit_kwd REAL,
                customer_username TEXT,
                date TEXT DEFAULT (datetime('now','localtime'))
            )
        """)
        # Check if merchant_username exists; if not, add it
        cur = db.execute("PRAGMA table_info(transactions)")
        columns = [row['name'] for row in cur.fetchall()]
        if 'merchant_username' not in columns:
            db.execute("ALTER TABLE transactions ADD COLUMN merchant_username TEXT")

        # Create settings table
        db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        cur = db.execute("SELECT value FROM settings WHERE key = 'exchange_rate'")
        if not cur.fetchone():
            db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ('exchange_rate', '422'))
        db.commit()

def get_exchange_rate():
    db = get_db()
    cur = db.execute("SELECT value FROM settings WHERE key = 'exchange_rate'")
    row = cur.fetchone()
    if row:
        try:
            return float(row['value'])
        except ValueError:
            return 422
    return 422

def set_exchange_rate(new_rate):
    db = get_db()
    db.execute("UPDATE settings SET value = ? WHERE key = 'exchange_rate'", (str(new_rate),))
    db.commit()

# ----- Routes -----
@app.route("/")
def home():
    if "user" in session:
        if not session.get("2fa_verified"):
            return redirect(url_for("two_factor"))
        return redirect(url_for("dashboard"))
    elif session.get("customer_logged_in"):
        return redirect(url_for("customer"))
    elif session.get("merchant_logged_in"):
        return redirect(url_for("merchant"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email in users and check_password_hash(users[email], password):
            session.clear()
            session["user"] = email
            session["username"] = email
            session["2fa_verified"] = False
            return redirect(url_for("two_factor"))

        elif email in customers and check_password_hash(customers[email], password):
            session.clear()
            session["customer_logged_in"] = True
            session["customer_username"] = email
            session["username"] = email
            return redirect(url_for("customer"))

        elif email in merchants and check_password_hash(merchants[email], password):
            session.clear()
            session["merchant_logged_in"] = True
            session["merchant_username"] = email
            session["username"] = email
            return redirect(url_for("merchant"))

        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not email or not password or not confirm_password:
            flash("Please fill out all fields.", "danger")
            return render_template("signup.html")

        import re
        email_pattern = r"[^@]+@[^@]+\.[^@]+"
        if not re.match(email_pattern, email):
            flash("Please enter a valid email address.", "danger")
            return render_template("signup.html")

        if len(password) < 5 or not any(char.isdigit() for char in password):
            flash("Password must be at least 5 characters and contain at least one number.", "danger")
            return render_template("signup.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("signup.html")

        if email in users or email in customers or email in merchants:
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for("login"))

        # Default new signup as customer
        customers[email] = generate_password_hash(password)
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/two_factor", methods=["GET", "POST"])
def two_factor():
    if "user" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        token = request.form.get("token")
        if token == "123456":
            session["2fa_verified"] = True
            flash("Two-factor authentication successful.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid authentication code.", "danger")
            return redirect(url_for("two_factor"))
    return render_template("two_factor.html")

# ----- Admin Dashboard -----
@app.route("/dashboard")
def dashboard():
    if "user" not in session or not session.get("2fa_verified"):
        flash("Please log in and complete 2FA to access the dashboard.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    exchange_rate = get_exchange_rate()
    username = session.get("username")
    all_logs = db.execute("SELECT * FROM transactions ORDER BY date ASC").fetchall()

    total_transactions = len(all_logs)
    total_profit_kwd = sum([row['profit_kwd'] for row in all_logs])

    from collections import defaultdict
    daily_data = defaultdict(lambda: {'count': 0, 'profit': 0})
    for row in all_logs:
        date_str = row['date'].split(' ')[0]
        daily_data[date_str]['count'] += row['amount_kwd']
        daily_data[date_str]['profit'] += row['profit_kwd']

    daily_labels = sorted(daily_data.keys())
    daily_counts = [daily_data[d]['count'] for d in daily_labels]
    daily_profits = [daily_data[d]['profit'] for d in daily_labels]

    recent_logs = db.execute("SELECT * FROM transactions ORDER BY date DESC LIMIT 10").fetchall()

    return render_template(
        "dashboard.html",
        username=username,
        exchange_rate=exchange_rate,
        total_transactions=total_transactions,
        total_profit_kwd=total_profit_kwd,
        daily_labels=daily_labels,
        daily_counts=daily_counts,
        daily_profits=daily_profits,
        logs=recent_logs
    )

# ----- Add Transaction -----
@app.route("/add_transaction", methods=["POST"])
def add_transaction():
    if not any([session.get("user"), session.get("customer_logged_in"), session.get("merchant_logged_in")]):
        flash("Please log in to add transactions.", "warning")
        return redirect(url_for("login"))

    try:
        amount_kwd = float(request.form.get("amount_kwd"))
    except (TypeError, ValueError):
        flash("Please enter a valid number for amount.", "danger")
        return redirect(request.referrer or url_for("home"))

    amount_kwd, msg = clamp_amount(amount_kwd)
    if msg:
        flash(msg, "warning")

    exchange_rate = get_exchange_rate()
    amount_kes = amount_kwd * exchange_rate
    safaricom_fee_kwd = get_safaricom_fee(amount_kes) / exchange_rate
    margin_kwd = calculate_dynamic_margin(amount_kwd, safaricom_fee_kwd, DISTRIBUTOR_FEE_KWD)

    db = get_db()
    db.execute(
        "INSERT INTO transactions (amount_kwd, amount_kes, profit_kwd, customer_username, merchant_username) VALUES (?, ?, ?, ?, ?)",
        (
            amount_kwd,
            amount_kwd * exchange_rate,
            margin_kwd,
            session.get('customer_username'),
            session.get('merchant_username')
        )
    )
    db.commit()

    flash(f"Transaction processed: {amount_kwd:.4f} KWD -> {amount_kes:.2f} KES, Profit: {margin_kwd:.4f} KWD", "success")
    return redirect(request.referrer or url_for("home"))

# ----- Merchant Routes -----
@app.route("/merchant")
def merchant():
    if not session.get('merchant_logged_in'):
        flash("Please log in as merchant to access this page.", "warning")
        return redirect(url_for('login'))

    db = get_db()
    username = session.get("merchant_username")
    transactions = db.execute(
        "SELECT * FROM transactions WHERE merchant_username = ? ORDER BY date DESC", 
        (username,)
    ).fetchall()

    return render_template("merchant.html", transactions=transactions, merchant_email=username)

@app.route("/merchant_logout")
def merchant_logout():
    session.clear()
    return redirect(url_for('login'))

# ----- Admin Exchange Rate -----
@app.route('/admin/exchange_rate', methods=['GET', 'POST'])
def admin_exchange_rate():
    if "user" not in session or not session.get("2fa_verified"):
        flash("Please log in and complete 2FA to access this page.", "warning")
        return redirect(url_for("login"))

    if request.method == 'POST':
        try:
            new_rate = float(request.form.get('exchange_rate'))
            if new_rate <= 0:
                raise ValueError
        except (TypeError, ValueError):
            flash("Please enter a valid positive number for exchange rate.", "danger")
            return redirect(url_for('admin_exchange_rate'))

        set_exchange_rate(new_rate)
        flash(f"Exchange rate updated to {new_rate}", "success")
        return redirect(url_for('admin_exchange_rate'))

    current_rate = get_exchange_rate()
    return render_template('admin_exchange_rate.html', exchange_rate=current_rate)

# ----- Customer Routes -----
@app.route('/customer', methods=['GET', 'POST'])
def customer():
    if not session.get('customer_logged_in'):
        return redirect(url_for('login'))

    exchange_rate = get_exchange_rate()
    username = session.get("username")

    if request.method == 'POST':
        try:
            amount_kwd = float(request.form.get('amount_kwd'))
        except (TypeError, ValueError):
            flash("Please enter a valid number for amount.", "danger")
            return render_template('customer_dashboard.html', exchange_rate=exchange_rate, username=username)

        amount_kwd, msg = clamp_amount(amount_kwd)
        if msg:
            flash(msg, "warning")

        amount_kes = amount_kwd * exchange_rate
        safaricom_fee_kwd = get_safaricom_fee(amount_kes) / exchange_rate
        margin_kwd = calculate_dynamic_margin(amount_kwd, safaricom_fee_kwd, DISTRIBUTOR_FEE_KWD)

        db = get_db()
        db.execute(
            "INSERT INTO transactions (amount_kwd, amount_kes, profit_kwd, customer_username) VALUES (?, ?, ?, ?)",
            (amount_kwd, amount_kes, margin_kwd, session.get('customer_username'))
        )
        db.commit()

        flash(f"Transaction processed: {amount_kwd:.4f} KWD -> {amount_kes:.2f} KES, Profit: {margin_kwd:.4f} KWD", "success")
        return render_template('customer_dashboard.html', exchange_rate=exchange_rate, username=username)

    return render_template('customer_dashboard.html', exchange_rate=exchange_rate, username=username)

@app.route("/my_transactions")
def my_transactions():
    if not session.get('customer_logged_in'):
        flash("Please log in to view your transactions.", "warning")
        return redirect(url_for('login'))

    username = session.get('customer_username')
    db = get_db()
    transactions = db.execute(
        "SELECT * FROM transactions WHERE customer_username = ? ORDER BY date DESC",
        (username,)
    ).fetchall()
    return render_template("my_transactions.html", transactions=transactions)

@app.route('/customer_logout')
def customer_logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/all_transactions")
def all_transactions():
    if "user" not in session or not session.get("2fa_verified"):
        flash("Please log in and complete 2FA to access this page.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    transactions = db.execute("SELECT * FROM transactions ORDER BY date DESC").fetchall()
    return render_template("all_transactions.html", transactions=transactions)


from flask import Response
import csv
import io

from flask import jsonify

@app.route("/export_transactions_json")
def export_transactions_json():
    try:
        db = get_db()
        transactions = db.execute("SELECT * FROM transactions ORDER BY id DESC").fetchall()

        data = []
        for tx in transactions:
            data.append({
                "id": tx["id"],
                "amount_kwd": float(tx["amount_kwd"]),
                "amount_kes": float(tx["amount_kes"]),
                "profit_kwd": float(tx["profit_kwd"]),
                "customer_username": tx["customer_username"] or "N/A",
                "date": tx["date"]
            })

        return jsonify({"transactions": data})
    except Exception as e:
        print("Error exporting transactions:", e)
        return jsonify({"error": "Failed to fetch transactions"}), 500


# ----- Run App -----
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
