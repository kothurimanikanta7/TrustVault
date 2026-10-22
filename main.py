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

def write_audit_log(actor_id: str, action: str, resource_id: str, log_status: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT current_hash FROM audit_trail ORDER BY timestamp DESC LIMIT 1")
    row = cursor.fetchone()
    previous_hash = row[0] if row else "GENESIS_BLOCK_HASH_0000000000000000000000"
    log_id = secrets.token_hex(16)
    timestamp = datetime.now(timezone.utc).isoformat()
    payload_str = f"{timestamp}|{actor_id}|{action}|{resource_id}|{log_status}|{previous_hash}"
    current_hash = hashlib.sha256(payload_str.encode()).hexdigest()
    cursor.execute("""
        INSERT INTO audit_trail (id, timestamp, actor_id, action, resource_id, status, previous_hash, current_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (log_id, timestamp, actor_id, action, resource_id, log_status, previous_hash, current_hash))
    conn.commit()
    conn.close()

MOCK_TOKENS = {
    "token_alice": {"id": "usr_alice", "role": "owner"},
    "token_bob": {"id": "usr_bob", "role": "viewer"},
    "token_eve": {"id": "usr_eve", "role": "admin"}
}

def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security_agent)):
    token = credentials.credentials
    if token not in MOCK_TOKENS:
        raise HTTPException(status_code=401, detail="Invalid Session Token")
    return MOCK_TOKENS[token]

def verify_access(document_id: str, current_user: dict, required_access: List[str]):
    user_id = current_user["id"]
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM documents WHERE id = ?", (document_id,))
    doc = cursor.fetchone()
    if not doc:
        conn.close()
        write_audit_log(user_id, "ACCESS_ATTEMPT_NONEXISTENT", document_id, "DENIED")
        raise HTTPException(status_code=404, detail="Document not found.")
    if doc["owner_id"] == user_id:
        conn.close()
        return doc
    cursor.execute("SELECT access_type FROM permissions WHERE document_id = ? AND user_id = ?", (document_id, user_id))
    permission = cursor.fetchone()
    conn.close()
    if permission and permission["access_type"] in required_access:
        return doc
    write_audit_log(user_id, "UNAUTHORIZED_READ_ATTEMPT", document_id, "DENIED")
    raise HTTPException(status_code=403, detail="Access Denied.")

@app.post("/api/documents", status_code=201)
def upload_document(title: str, category: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "owner":
        raise HTTPException(status_code=403, detail="Only owners can upload.")
    doc_id = f"doc_{secrets.token_hex(4)}"
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO documents (id, title, category, owner_id) VALUES (?, ?, ?, ?)", (doc_id, title, category, current_user["id"]))
    conn.commit()
    conn.close()
    write_audit_log(current_user["id"], "DOCUMENT_UPLOADED", doc_id, "SUCCESS")
    return {"document_id": doc_id, "status": "Document safely locked in vault"}

@app.get("/api/documents/{document_id}")
def read_document(document_id: str, current_user: dict = Depends(get_current_user)):
    doc = verify_access(document_id, current_user, ["read", "edit"])
    write_audit_log(current_user["id"], "DOCUMENT_READ", document_id, "SUCCESS")
    return {"id": doc["id"], "title": doc["title"], "category": doc["category"], "content": "DECRYPTED_SECRET_DATA"}

@app.get("/api/admin/audit")
def view_audit_trail(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin authorization required.")
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_trail ORDER BY timestamp DESC")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

init_db()
