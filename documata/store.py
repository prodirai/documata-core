import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import time
from contextlib import contextmanager

class Problem(Exception):
    def __init__(self, code, message, status=409):
        super().__init__(message)
        self.code, self.status = code, status

def require(condition, code="ACCESS_DENIED", message="Для этого действия нужны другие права.", status=403):
    if not condition:
        raise Problem(code, message, status)

def found(row):
    require(row is not None, "NOT_FOUND", "Запись недоступна.", 404)
    return row

def digest(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

def token():
    return secrets.token_urlsafe(24)

class Store:
    def __init__(self, path, clock=time.time):
        self.root = Path(path).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.blobs = self.root / "objects"
        self.blobs.mkdir(mode=0o700, exist_ok=True)
        self.clock = clock
        key = self.root / "registry.secret"
        if not key.exists():
            self.install(key, secrets.token_bytes(32))
        self.key = key.read_bytes()
        with self.transaction() as db:
            db.executescript(Path(__file__).with_name("schema.sql").read_text())
            for table in ("signatures","events","revisions"):
                for action in ("UPDATE","DELETE"):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS immutable_{table}_{action} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'immutable record'); END")

    def now(self):
        return int(self.clock())

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.root / "registry.sqlite3", timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def install(path, content):
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
            try:
                tmp.write(content)
                tmp.flush()
                os.fsync(tmp.fileno())
                os.link(tmp.name, path)
            except FileExistsError:
                pass
            finally:
                os.unlink(tmp.name)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def put(self, content):
        checksum = digest(content)
        self.install(self.blobs / checksum, content)
        self.read(checksum)
        return checksum

    def read(self, checksum):
        import re
        require(re.fullmatch("[a-f0-9]{64}",checksum), "INTEGRITY", "Неверная ссылка на оригинал.", 503)
        try:
            content = (self.blobs / checksum).read_bytes()
        except FileNotFoundError:
            content = b""
        require(content and hmac.compare_digest(digest(content),checksum), "INTEGRITY", "Оригинал недоступен. Подписание остановлено.", 503)
        return content

    def proof(self, purpose, value):
        return hmac.new(self.key,(purpose+"\0"+value).encode(),hashlib.sha256).hexdigest()
