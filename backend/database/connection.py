"""
RansomShield Database Connection & Session Management
Uses SQLite for research deployment via SQLAlchemy ORM.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "ransomshield.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.abspath(DB_PATH)}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    Base.metadata.create_all(bind=engine)
    try:
        with engine.connect() as conn:
            from sqlalchemy import text
            for col, col_type in [("alert_type", "VARCHAR(100) DEFAULT 'SUSPICIOUS_BEHAVIOR'"),
                                  ("cpu_usage", "FLOAT DEFAULT 0.0"),
                                  ("ram_usage", "FLOAT DEFAULT 0.0")]:
                try:
                    conn.execute(text(f"ALTER TABLE alerts ADD COLUMN {col} {col_type}"))
                    conn.commit()
                except Exception:
                    pass
    except Exception:
        pass
