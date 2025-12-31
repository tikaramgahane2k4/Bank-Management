import os

class Config:
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "postgresql://student_ms_db_1i7f_user:oGpNiDNenVW5TjjLWOba66hcMtd3YqG0@dpg-d57c6peuk2gs73cvb8qg-a.oregon-postgres.render.com/bank_data"
    SQLALCHEMY_TRACK_MODIFICATION = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "student@123")