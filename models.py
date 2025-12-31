from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(200), nullable=False)
    
    # New Onboarding Fields
    phone = db.Column(db.String(20))
    address = db.Column(db.Text)
    id_number = db.Column(db.String(50))
    city = db.Column(db.String(100))
    pin_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)
    is_profile_complete = db.Column(db.Boolean, default=False)

    accounts = db.relationship("Account", backref="user")

    def set_password(self, password):
        self.password = generate_password_hash(password, method="pbkdf2:sha256")

    def check_password(self, password):
        return check_password_hash(self.password, password)
        
    def set_pin(self, pin):
        self.pin_hash = generate_password_hash(pin, method="pbkdf2:sha256")
        
    def check_pin(self, pin):
        if not self.pin_hash:
            return False
        return check_password_hash(self.pin_hash, pin)
    
class Account(db.Model):
    __tablename__ = "accounts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    account_number = db.Column(db.String(20), unique=True)
    balance = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default="active")
    account_type = db.Column(db.String(50))
    branch = db.Column(db.String(100))

class Transaction(db.Model):
    __tablename__ = "transactions"
    id = db.Column(db.Integer, primary_key=True)
    from_account = db.Column(db.String(20))
    to_account = db.Column(db.String(20))
    amount = db.Column(db.Float)
    type = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default = datetime.utcnow)