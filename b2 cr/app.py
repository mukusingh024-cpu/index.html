import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parent
DATABASE = ROOT / "hospital.db"
ADMIN_USERNAME = os.environ.get("CAREHUB_ADMIN_USER", "sumit")
ADMIN_PASSWORD = os.environ.get("CAREHUB_ADMIN_PASSWORD", "5134")
USER_USERNAME = os.environ.get("CAREHUB_USER_USERNAME", "b1")
USER_PASSWORD = os.environ.get("CAREHUB_USER_PASSWORD", "185")
SESSION_COOKIE = "carehub_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PASSWORD_SALT = b"carehub-admin-password-v1"
ACCOUNTS = (
    {
        "username": ADMIN_USERNAME,
        "password_hash": hashlib.pbkdf2_hmac(
            "sha256", ADMIN_PASSWORD.encode("utf-8"), PASSWORD_SALT, 300_000
        ),
        "role": "admin",
    },
    {
        "username": USER_USERNAME,
        "password_hash": hashlib.pbkdf2_hmac(
            "sha256", USER_PASSWORD.encode("utf-8"), PASSWORD_SALT, 300_000
        ),
        "role": "user",
    },
)
SESSIONS = {}
SESSIONS_LOCK = threading.Lock()
COLLECTIONS = {
    "patients": {
        "fields": {"name", "age", "gender", "department", "doctor", "date", "status"},
        "required": {"name", "age", "gender", "department", "doctor", "date"},
        "numbers": {"age"},
    },
    "appointments": {
        "fields": {"patient", "doctor", "department", "date", "time", "status"},
        "required": {"patient", "doctor", "department", "date", "time", "status"},
        "numbers": set(),
    },
    "doctors": {
        "fields": {"name", "specialty", "phone", "schedule"},
        "required": {"name", "specialty"},
        "numbers": set(),
    },
    "medicines": {
        "fields": {"name", "quantity", "expiry", "price"},
        "required": {"name", "quantity"},
        "numbers": {"quantity", "price"},
    },
    "bills": {
        "fields": {"patient", "description", "amount", "status"},
        "required": {"patient", "description", "amount", "status"},
        "numbers": {"amount"},
    },
}


def connect_database():
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with connect_database() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS records (
                collection TEXT NOT NULL,
                id TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch()),
                PRIMARY KEY (collection, id)
            )
            """
        )


class HospitalHandler(BaseHTTPRequestHandler):
    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def session_token(self):
        cookie_header = self.headers.get("Cookie", "")
        for cookie in cookie_header.split(";"):
            name, separator, value = cookie.strip().partition("=")
            if separator and name == SESSION_COOKIE:
                return value
        return None

    def is_authenticated(self):
        return self.current_session() is not None

    def current_session(self):
        token = self.session_token()
        if not token:
            return None
        now = time.time()
        with SESSIONS_LOCK:
            for session_id, session in list(SESSIONS.items()):
                if session["expires_at"] <= now:
                    del SESSIONS[session_id]
            return SESSIONS.get(token)

    def require_authentication(self):
        return self.require_role()

    def require_role(self, role=None):
        session = self.current_session()
        if session is None:
            self.send_json(401, {"error": "Please sign in to continue."})
            return False
        if role and session["role"] != role:
            self.send_json(403, {"error": "Administrator access is required."})
            return False
        return True

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 1_000_000:
                raise ValueError("Request body must be between 1 byte and 1 MB.")
            value = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError) as error:
            raise ValueError("Request body must contain valid JSON.") from error
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    @staticmethod
    def normalize_record(collection, payload, existing=None):
        schema = COLLECTIONS[collection]
        if set(payload) - schema["fields"]:
            raise ValueError("Record contains unsupported fields.")
        record = dict(existing or {})
        record.update(payload)
        missing = [field for field in schema["required"] if field not in record or record[field] in ("", None)]
        if missing:
            raise ValueError(f"Required fields missing: {', '.join(sorted(missing))}.")
        for field in schema["fields"]:
            if field not in record:
                continue
            value = record[field]
            if field in schema["numbers"]:
                if value == "" and field not in schema["required"]:
                    record[field] = None
                    continue
                try:
                    number = float(value)
                except (TypeError, ValueError) as error:
                    raise ValueError(f"{field} must be a number.") from error
                if number < 0:
                    raise ValueError(f"{field} cannot be negative.")
                if field in {"age", "quantity"} and not number.is_integer():
                    raise ValueError(f"{field} must be a whole number.")
                record[field] = int(number) if number.is_integer() else number
            elif value is not None:
                record[field] = str(value).strip()
        if collection == "patients" and not 1 <= record["age"] <= 120:
            raise ValueError("age must be between 1 and 120.")
        return record

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.serve_index()
            return
        if path == "/api/session":
            session = self.current_session()
            self.send_json(
                200,
                {
                    "authenticated": session is not None,
                    "username": session["username"] if session else None,
                    "role": session["role"] if session else None,
                },
            )
            return
        if not self.require_authentication():
            return
        if path != "/api/records":
            self.send_json(404, {"error": "Not found."})
            return
        result = {name: [] for name in COLLECTIONS}
        with connect_database() as connection:
            rows = connection.execute(
                "SELECT collection, id, data FROM records ORDER BY created_at DESC, rowid DESC"
            )
            for row in rows:
                result[row["collection"]].append(
                    {"id": row["id"], **json.loads(row["data"])}
                )
        self.send_json(200, result)

    def do_POST(self):
        parts = [unquote(part) for part in urlparse(self.path).path.strip("/").split("/")]
        if parts == ["api", "login"]:
            try:
                payload = self.read_json()
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
                return
            username = str(payload.get("username", ""))
            password = str(payload.get("password", ""))
            password_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), PASSWORD_SALT, 300_000
            )
            account = next(
                (
                    candidate
                    for candidate in ACCOUNTS
                    if hmac.compare_digest(username, candidate["username"])
                    & hmac.compare_digest(password_hash, candidate["password_hash"])
                ),
                None,
            )
            if account is None:
                self.send_json(401, {"error": "Username or password is incorrect."})
                return
            token = secrets.token_urlsafe(32)
            with SESSIONS_LOCK:
                SESSIONS[token] = {
                    "username": account["username"],
                    "role": account["role"],
                    "expires_at": time.time() + SESSION_TTL_SECONDS,
                }
            self.send_json(
                200,
                {
                    "authenticated": True,
                    "username": account["username"],
                    "role": account["role"],
                },
                {
                    "Set-Cookie": (
                        f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; "
                        f"Path=/; Max-Age={SESSION_TTL_SECONDS}"
                    )
                },
            )
            return
        if parts == ["api", "logout"]:
            token = self.session_token()
            if token:
                with SESSIONS_LOCK:
                    SESSIONS.pop(token, None)
            self.send_json(
                200,
                {"authenticated": False},
                {"Set-Cookie": f"{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"},
            )
            return
        if not self.require_authentication():
            return
        if len(parts) != 2 or parts[0] != "api" or parts[1] not in COLLECTIONS:
            self.send_json(404, {"error": "Unknown record collection."})
            return
        collection = parts[1]
        try:
            record = self.normalize_record(collection, self.read_json())
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        record_id = str(uuid.uuid4())
        with connect_database() as connection:
            connection.execute(
                "INSERT INTO records (collection, id, data) VALUES (?, ?, ?)",
                (collection, record_id, json.dumps(record, ensure_ascii=False)),
            )
        self.send_json(201, {"id": record_id, **record})

    def do_PUT(self):
        if not self.require_role("admin"):
            return
        parts = [unquote(part) for part in urlparse(self.path).path.strip("/").split("/")]
        if len(parts) != 3 or parts[0] != "api" or parts[1] not in COLLECTIONS:
            self.send_json(404, {"error": "Unknown record."})
            return
        collection, record_id = parts[1], parts[2]
        try:
            payload = self.read_json()
            with connect_database() as connection:
                row = connection.execute(
                    "SELECT data FROM records WHERE collection = ? AND id = ?",
                    (collection, record_id),
                ).fetchone()
                if row is None:
                    self.send_json(404, {"error": "Record not found."})
                    return
                record = self.normalize_record(
                    collection, payload, json.loads(row["data"])
                )
                connection.execute(
                    "UPDATE records SET data = ? WHERE collection = ? AND id = ?",
                    (json.dumps(record, ensure_ascii=False), collection, record_id),
                )
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        self.send_json(200, {"id": record_id, **record})

    def do_DELETE(self):
        if not self.require_role("admin"):
            return
        path = urlparse(self.path).path
        if path == "/api/records":
            with connect_database() as connection:
                connection.execute("DELETE FROM records")
            self.send_json(200, {"deleted": True})
            return
        parts = [unquote(part) for part in path.strip("/").split("/")]
        if len(parts) != 3 or parts[0] != "api" or parts[1] not in COLLECTIONS:
            self.send_json(404, {"error": "Unknown record."})
            return
        with connect_database() as connection:
            cursor = connection.execute(
                "DELETE FROM records WHERE collection = ? AND id = ?",
                (parts[1], parts[2]),
            )
        if cursor.rowcount == 0:
            self.send_json(404, {"error": "Record not found."})
            return
        self.send_json(200, {"deleted": True})

    def serve_index(self):
        try:
            body = (ROOT / "templates" / "index.html").read_bytes()
        except OSError:
            self.send_json(500, {"error": "The dashboard template could not be loaded."})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}")


if __name__ == "__main__":
    initialize_database()
    server = ThreadingHTTPServer(("127.0.0.1", 8000), HospitalHandler)
    print("CareHub running at http://127.0.0.1:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCareHub server stopped.")
    finally:
        server.server_close()
