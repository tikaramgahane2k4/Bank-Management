from flask import Flask, render_template, request, redirect, url_for, flash
from config import Config
from models import db, User, Account, Transaction
from sqlalchemy import text
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def profile_complete_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            flash("Admin access required.", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated


with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        # If DB is not reachable (e.g., remote Postgres not available), continue so the
        # development server can start. Real deployments should ensure DB connectivity.
        print("Warning: could not create DB tables on startup:", e)

    # Ensure newly added optional columns exist for older databases.
    # This is a lightweight, best-effort migration for development environments.
    try:
        engine_name = db.engine.dialect.name
        # accounts table check
        if engine_name == 'postgresql':
            res = db.session.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='accounts';"))
            account_cols = [r[0] for r in res]
            res = db.session.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='users';"))
            user_cols = [r[0] for r in res]
        elif engine_name == 'sqlite':
            res = db.session.execute(text("PRAGMA table_info('accounts');"))
            account_cols = [r[1] for r in res]
            res = db.session.execute(text("PRAGMA table_info('users');"))
            user_cols = [r[1] for r in res]
        else:
            res = db.session.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='accounts';"))
            account_cols = [r[0] for r in res]
            res = db.session.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='users';"))
            user_cols = [r[0] for r in res]

        alter_needed = []
        if 'account_type' not in account_cols:
            alter_needed.append("ALTER TABLE accounts ADD COLUMN account_type VARCHAR;")
        if 'branch' not in account_cols:
            alter_needed.append("ALTER TABLE accounts ADD COLUMN branch VARCHAR;")
        if 'username' not in user_cols:
            alter_needed.append("ALTER TABLE users ADD COLUMN username VARCHAR;")

        for sql in alter_needed:
            try:
                db.session.execute(text(sql))
                db.session.commit()
                print("Added column via:", sql)
            except Exception as ae:
                print("Warning: could not add column:", ae)
    except Exception as e:
        print("Warning: migration check failed:", e)

    # Ensure there is a default admin user for initial access
    try:
        admin_email = 'admin@trustbank.local'
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
            admin = User(name='Administrator', email=admin_email, username='admin')
            admin.set_password('adminpass')
            admin.is_admin = True
            db.session.add(admin)
            db.session.commit()
            print('Created default admin:', admin_email)
    except Exception as e:
        print('Warning: could not ensure default admin:', e)


# ------- Authentication -------


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        # If user is logged in and already has an account, redirect to dashboard
        if Account.query.filter_by(user_id=current_user.id).first():
            return redirect(url_for("account"))
        # If logged in but no account, let them stay (they might be on the onboarding form)
        # But register page is for new Users. For existing users without accounts, we show form on /account.
        return redirect(url_for("account"))

    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        if not (name and email and password):
            flash("Please fill all fields", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please login.", "info")
            return redirect(url_for("login"))

        user = User(name=name, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please login to open your account.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin_accounts"))
        return redirect(url_for("account"))
        
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if user.is_admin:
                flash("Please use the Admin Login page.", "warning")
                return redirect(url_for("admin_login"))
            login_user(user)
            return redirect(url_for("account"))
        else:
            flash("Invalid email or password", "error")
    return render_template("login.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for("admin_accounts"))
        
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password) and user.is_admin:
            login_user(user)
            return redirect(url_for("admin_accounts"))
        else:
            flash("Invalid admin credentials", "error")
    return render_template("admin_login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("account"))
        
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if user:
            # In a real app, send an email. Here we redirect to reset page for demo.
            flash("Account identified. Please set your new password.", "info")
            return redirect(url_for("reset_password", user_id=user.id))
        else:
            flash("Email not found.", "error")
    return render_template("forgot_password.html")


@app.route("/reset-password/<int:user_id>", methods=["GET", "POST"])
def reset_password(user_id):
    if current_user.is_authenticated:
        return redirect(url_for("account"))
        
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        
        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("reset_password", user_id=user_id))
            
        user.set_password(password)
        db.session.commit()
        flash("Password reset successful. Please login.", "success")
        return redirect(url_for("login"))
        
    return render_template("reset_password.html", user_id=user_id)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ------- Pages -------


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/account")
@login_required
def account():
    user_accounts = Account.query.filter_by(user_id=current_user.id).all()
    # If user has no account, generate a candidate account number to show on the form
    generated_account = None
    if not user_accounts:
        generated_account = None
        # generate a non-committed unique account number
        def gen_number():
            import random
            return str(random.randint(10000000, 99999999))

        candidate = gen_number()
        while Account.query.filter_by(account_number=candidate).first():
            candidate = gen_number()
        generated_account = candidate

    return render_template("account.html", user=current_user, accounts=user_accounts, generated_account=generated_account)


@app.route("/account/open", methods=["POST"])
@login_required
def open_account():
    # Read extended form fields: owner identity, personal details and bank details
    name = request.form.get('name')
    username = request.form.get('username')
    email = request.form.get('email')
    phone = request.form.get('phone')
    address = request.form.get('address')
    city = request.form.get('city')
    id_number = request.form.get('id_number')
    pin = request.form.get('pin')
    branch = request.form.get('branch')
    account_type = request.form.get('account_type')

    # Validate required identity and PIN
    if not (name and username and email):
        flash("Please provide name, username and email.", "error")
        return redirect(url_for('account'))

    if not pin or len(pin) != 6 or not pin.isdigit():
        flash("PIN must be exactly 6 digits.", "error")
        return redirect(url_for('account'))

    # Ensure email/username uniqueness if changed
    if email != current_user.email:
        other = User.query.filter_by(email=email).first()
        if other and other.id != current_user.id:
            flash("Email already in use by another account.", "error")
            return redirect(url_for('account'))

    if username and username != getattr(current_user, 'username', None):
        otheru = User.query.filter_by(username=username).first()
        if otheru and otheru.id != current_user.id:
            flash("Username already in use.", "error")
            return redirect(url_for('account'))

    # Save/overwrite personal details to user
    current_user.name = name
    current_user.username = username
    current_user.email = email
    current_user.phone = phone
    current_user.address = address
    current_user.city = city
    current_user.id_number = id_number
    current_user.set_pin(pin)
    db.session.add(current_user)
    db.session.commit()

    # server-side ensure unique account number
    account_number = request.form.get("account_number") or None
    if not account_number:
        import random
        account_number = str(random.randint(10000000, 99999999))
        while Account.query.filter_by(account_number=account_number).first():
            account_number = str(random.randint(10000000, 99999999))

    # prevent duplicate accounts for same user
    # Interpret "add another" as allowing multiple accounts (limit 5)
    existing_accounts_count = Account.query.filter_by(user_id=current_user.id).count()
    if existing_accounts_count >= 5:
        flash("You have reached the maximum limit of 5 accounts.", "warning")
        return redirect(url_for("account"))

    new_account = Account(user_id=current_user.id, account_number=account_number, balance=0.0, status='active', account_type=account_type, branch=branch)
    db.session.add(new_account)
    db.session.commit()
    flash(f"Account {account_number} opened successfully.", "success")
    return redirect(url_for('account_created', account_number=account_number))


@app.route("/account/<account_number>")
@login_required
def account_details(account_number):
    account = Account.query.filter_by(account_number=account_number, user_id=current_user.id).first_or_404()
    transactions = Transaction.query.filter((Transaction.from_account == account_number) | (Transaction.to_account == account_number)).order_by(Transaction.created_at.desc()).all()
    return render_template("account_details.html", user=current_user, account=account, transactions=transactions)


# ------- Admin -------


@app.route('/admin/accounts')
@login_required
@admin_required
def admin_accounts():
    # show all accounts with owner info
    accounts = Account.query.order_by(Account.id.desc()).all()
    return render_template('admin_accounts.html', accounts=accounts)


@app.route('/admin/account/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_account():
    acc_num = request.form.get('account_number')
    if not acc_num:
        flash('Account number required.', 'error')
        return redirect(url_for('admin_accounts'))

    account = Account.query.filter_by(account_number=acc_num).first()
    if not account:
        flash('Account not found.', 'error')
        return redirect(url_for('admin_accounts'))

    # Remove related transactions (optional)
    try:
        Transaction.query.filter((Transaction.from_account == acc_num) | (Transaction.to_account == acc_num)).delete(synchronize_session=False)
        db.session.delete(account)
        db.session.commit()
        flash(f'Account {acc_num} deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Could not delete account: ' + str(e), 'error')

    return redirect(url_for('admin_accounts'))


@app.route('/admin/account/<account_number>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_account(account_number):
    account = Account.query.filter_by(account_number=account_number).first_or_404()
    if request.method == 'POST':
        status = request.form.get('status')
        account_type = request.form.get('account_type')
        branch = request.form.get('branch')
        balance = request.form.get('balance')
        owner_email = request.form.get('owner_email')
        try:
            if status:
                account.status = status
            if account_type:
                account.account_type = account_type
            if branch is not None:
                account.branch = branch
            if balance:
                account.balance = float(balance)
            if owner_email:
                user = User.query.filter_by(email=owner_email).first()
                if user:
                    account.user_id = user.id
            db.session.add(account)
            db.session.commit()
            flash(f'Account {account_number} updated.', 'success')
            return redirect(url_for('admin_accounts'))
        except Exception as e:
            db.session.rollback()
            flash('Could not update account: ' + str(e), 'error')
            return redirect(url_for('admin_edit_account', account_number=account_number))

    return render_template('admin_edit_account.html', account=account)


@app.route("/account/created/<account_number>")
@login_required
def account_created(account_number):
    account = Account.query.filter_by(account_number=account_number, user_id=current_user.id).first_or_404()
    # Example bank info to show after account creation
    bank_info = {
        'name': 'TrustBank',
        'support_email': 'support@trustbank.example',
        'phone': '+1-800-TRUST',
        'head_office': '123 Finance St, Capital City',
        'swift': 'TRUSTUSX'
    }
    return render_template('account_created.html', account=account, bank_info=bank_info)


@app.route("/deposit", methods=["POST"])
@login_required
def deposit():
    account_number = request.form.get("account_number")
    try:
        amount = float(request.form.get("amount"))
    except Exception:
        flash("Invalid amount.", "error")
        return redirect(url_for('account'))

    pin = request.form.get("pin")
    # If user has a PIN set, require it; otherwise allow
    if getattr(current_user, 'pin_hash', None):
        if not current_user.check_pin(pin):
            flash("Invalid security PIN.", "error")
            return redirect(url_for('account'))

    account = Account.query.filter_by(account_number=account_number, user_id=current_user.id).first()
    if not account:
        flash("Account not found or access denied.", "error")
        return redirect(url_for('account'))

    account.balance += amount
    tx = Transaction(from_account=None, to_account=account_number, amount=amount, type='deposit')
    db.session.add(tx)
    db.session.commit()
    flash(f"Deposited ${amount:.2f} to {account_number}.", "success")
    return redirect(url_for('account_details', account_number=account_number))


@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    from_account_num = request.form.get("from_account")
    to_account_num = request.form.get("to_account")
    try:
        amount = float(request.form.get("amount"))
    except Exception:
        flash("Invalid amount.", "error")
        return redirect(url_for('account'))

    pin = request.form.get("pin")
    if getattr(current_user, 'pin_hash', None):
        if not current_user.check_pin(pin):
            flash("Invalid security PIN.", "error")
            return redirect(url_for('account'))

    sender = Account.query.filter_by(account_number=from_account_num, user_id=current_user.id).first()
    receiver = Account.query.filter_by(account_number=to_account_num).first()

    if not sender:
        flash("Sender account not found or access denied.", "error")
        return redirect(url_for('account'))
    if not receiver:
        flash("Recipient account not found.", "error")
        return redirect(url_for('account'))
    if sender.balance < amount:
        flash("Insufficient balance.", "error")
        return redirect(url_for('account_details', account_number=from_account_num))

    sender.balance -= amount
    receiver.balance += amount
    tx = Transaction(from_account=from_account_num, to_account=to_account_num, amount=amount, type='transfer')
    db.session.add(tx)
    db.session.commit()
    flash(f"Transferred ${amount:.2f} to {to_account_num}.", "success")
    return redirect(url_for('account_details', account_number=from_account_num))


if __name__ == "__main__":
    app.run(debug=True, port=5005)
