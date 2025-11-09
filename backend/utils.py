import yaml, os, json, time, logging
from datetime import datetime
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData, Float, Text

def load_config(path="config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)

def ensure_dirs(paths):
    for p in paths:
        os.makedirs(p, exist_ok=True)

def setup_db(db_path):
    engine = create_engine(f"sqlite:///{db_path}", echo=False, future=True)
    meta = MetaData()
    alerts = Table('alerts', meta,
        Column('id', Integer, primary_key=True),
        Column('timestamp', String),
        Column('event_type', String),
        Column('src_ip', String),
        Column('dst_ip', String),
        Column('details', Text),
        Column('ml_score', Float, nullable=True)
    )
    meta.create_all(engine)
    return engine, alerts

def now_iso():
    return datetime.utcnow().isoformat() + "Z"
