from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
engine = create_engine(settings.database_url, pool_pre_ping=True, pool_size=10,
                       connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite:") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
