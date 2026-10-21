import secrets
import hashlib
from datetime import datetime, timezone
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import sqlite3

app = FastAPI(title="TrustVault Security System")
security_agent = HTTPBearer()
DB_FILE = "trustvault.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'owner', 'viewer'))
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS permissions (
        document_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        access_type TEXT NOT NULL CHECK(access_type IN ('read', 'edit')),
        PRIMARY KEY (document_id, user_id),
        FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_trail (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        action TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        status TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

init_db()
