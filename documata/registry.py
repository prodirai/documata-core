"""Document permissions and transitions. Mutating calls run inside Store.transaction()."""

from dataclasses import dataclass
import hmac
import json
import secrets

from .seal import RegistryKey
from .store import canonical, digest, found, require, token

RULES = "Учебные правила ПЭП v1. Отдельный одноразовый код подтверждает волю указанной стороны подписать показанную редакцию PDF. Храните код в тайне. Все подтверждения на стенде имитированы."
KINDS = ("Договор", "Приложение", "Акт", "Допсоглашение", "Счёт")


@dataclass(frozen=True)
class Actor:
    person: str
    org: str | None
    session: str


class Registry:
    def __init__(self, store):
        self.store = store
        self.key = RegistryKey(store)

    def member(self, db, actor):
        return db.execute(
            "SELECT * FROM members WHERE org=? AND person=?", (actor.org, actor.person)
        ).fetchone()

    def visible(self, db, actor):
        if actor.org:
            if not self.member(db, actor):
                return []
            rows = db.execute(
                "SELECT * FROM documents WHERE org=? ORDER BY rowid DESC", (actor.org,)
            )
        else:
            rows = db.execute(
                """SELECT d.* FROM documents d JOIN subjects s ON d.recipient=s.id
                WHERE d.recipient=? AND s.identity IS NOT NULL AND EXISTS
                (SELECT 1 FROM signatures g WHERE g.doc=d.id AND g.side='customer'  )
                ORDER BY d.rowid DESC""",
                (actor.person,),
            )
        return [self.document(db, actor, r["id"]) for r in rows]

    def document(self, db, actor, ident):
        row = found(
            db.execute("SELECT * FROM documents WHERE id=?", (ident,)).fetchone()
        )
        if actor.org:
            allowed = actor.org == row["org"] and self.member(db, actor)
        else:
            allowed = (
                row["recipient"] == actor.person
                and db.execute(
                    """SELECT MAX(revision) AS revision FROM signatures
                WHERE doc=? AND side='customer' AND EXISTS(SELECT 1 FROM subjects WHERE id=? AND identity IS NOT NULL)
                HAVING MAX(revision) IS NOT NULL""",
                    (ident, actor.person),
                ).fetchone()
            )
            if allowed and allowed["revision"] != row["revision"]:
                return {
                    **dict(row),
                    "revision": allowed["revision"],
                    "state": "superseded",
                }
        found(row if allowed else None)
        return dict(row)

    def editable(self, db, actor):
        member = self.member(db, actor)
        require(member and member["role"] in ("owner", "preparer", "signer"))

    def create(
        self,
        db,
        actor,
        title,
        recipient,
        signer,
        checksum,
        transcript,
        kind="Договор",
        parent=None,
        folder="Мои документы",
        price=0,
    ):
        self.editable(db, actor)
        require(
            kind in KINDS and 0 < len(title.strip()) <= 160 and 0 < len(folder) <= 80,
            "INVALID",
            "Проверьте название и вид документа.",
            422,
        )
        found(db.execute("SELECT 1 FROM subjects WHERE id=?", (recipient,)).fetchone())
        require(
            signer != recipient
            and db.execute(
                "SELECT 1 FROM members WHERE org=? AND person=? AND role IN ('signer','owner')",
                (actor.org, signer),
            ).fetchone()
        )
        if parent:
            base = self.document(db, actor, parent)
            require(
                base["parent"] is None
                and base["recipient"] == recipient
                and kind != "Договор"
            )
            folder = base["folder"]
        self.store.read(checksum)
        ident = token()
        db.execute(
            "INSERT INTO documents VALUES (?,?,?,?,?,?,?,?,1,'draft',?,?)",
            (
                ident,
                actor.org,
                recipient,
                signer,
                title.strip(),
                kind,
                parent,
                folder,
                RULES,
                price,
            ),
        )
        db.execute(
            "INSERT INTO revisions VALUES (?,1,?,?,?)",
            (ident, checksum, transcript, self.store.now()),
        )
        self.event(db, ident, 1, actor.person, "created")
        return ident

    def event(self, db, doc, revision, actor, action, detail=""):
        db.execute(
            "INSERT INTO events(doc,revision,actor,action,at,detail) VALUES(?,?,?,?,?,?)",
            (doc, revision, actor, action, self.store.now(), detail),
        )

    def version(self, db, doc, revision):
        return dict(
            found(
                db.execute(
                    "SELECT * FROM revisions WHERE doc=? AND revision=?",
                    (doc, revision),
                ).fetchone()
            )
        )

    def context(self, db, actor, ident, rev):
        doc = self.document(db, actor, ident)
        require(
            doc["revision"] == rev,
            "REVISION_CHANGED",
            "Откройте текущую редакцию.",
            409,
        )
        person = found(
            db.execute("SELECT * FROM subjects WHERE id=?", (actor.person,)).fetchone()
        )
        require(
            person["channel"] and person["identity"] and not person["blocked"],
            "IDENTITY_REQUIRED",
            "Сначала подтвердите канал и личность.",
            403,
        )
        side = "customer" if actor.org else "performer"
        member = self.member(db, actor)
        if actor.org:
            require(
                actor.person == doc["signer"]
                and member["authority"] > self.store.now()
                and member["role"] in ("owner", "signer"),
                "AUTHORITY_REQUIRED",
                "Требуются действующие полномочия назначенного подписанта.",
                403,
            )
        expected = "draft" if actor.org else "waiting"
        require(
            doc["state"] == expected,
            "CONFLICT",
            "Действие уже недоступно. Обновите карточку.",
            409,
        )
        version = self.version(db, ident, rev)
        self.store.read(version["digest"])
        org = found(
            db.execute(
                "SELECT name FROM organizations WHERE id=?", (doc["org"],)
            ).fetchone()
        )
        return {
            "schema_version": 1,
            "environment": "local",
            "assurance": "simulated",
            "document": ident,
            "title": doc["title"],
            "revision": rev,
            "sha256": version["digest"],
            "side": side,
            "subject": actor.person,
            "name": person["name"],
            "organization": doc["org"] if actor.org else None,
            "organization_name": org["name"] if actor.org else None,
            "authority_expires": member["authority"] if member else None,
            "identity_operation": person["identity"],
            "channel_operation": person["channel"],
            "rules": doc["rules"],
            "rules_sha256": digest(doc["rules"].encode()),
            "price_minor": doc["price"] if actor.org else 0,
        }

    def start(self, db, actor, ident, rev, viewed_hash, rules_hash, accepted, deliver):
        ctx = self.context(db, actor, ident, rev)
        require(
            accepted is True
            and viewed_hash == ctx["sha256"]
            and rules_hash == ctx["rules_sha256"],
            "CONSENT_REQUIRED",
            "Прочитайте PDF и примите показанные правила.",
            422,
        )
        now = self.store.now()
        recent = db.execute(
            "SELECT count(*),max(issued) FROM intents WHERE person=? AND issued>?",
            (actor.person, now - 3600),
        ).fetchone()
        require(
            recent[0] < 20 and (recent[1] is None or now - recent[1] >= 60),
            "RATE_LIMITED",
            "Следующий код можно запросить позднее.",
            429,
        )
        ident_intent, code = token(), f"{secrets.randbelow(1000000):06}"
        db.execute(
            "UPDATE intents SET expires=0 WHERE doc=? AND side=? AND committed=0",
            (ident, ctx["side"]),
        )
        db.execute(
            "INSERT INTO intents(id,person,session,doc,revision,side,context,verifier,issued,expires) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                ident_intent,
                actor.person,
                actor.session,
                ident,
                rev,
                ctx["side"],
                canonical(ctx),
                self.store.proof(ident_intent, code),
                now,
                now + 300,
            ),
        )
        deliver(ident_intent, code)
        return ident_intent

    def operation(self, db, actor, op):
        item = found(
            db.execute(
                "SELECT * FROM intents WHERE id=? AND person=? AND session=?",
                (op, actor.person, actor.session),
            ).fetchone()
        )
        self.document(db, actor, item["doc"])
        require(bool(actor.org) == (item["side"] == "customer"))
        return item

    def confirm(self, db, actor, op, code):
        item = self.operation(db, actor, op)
        if item["committed"]:
            return {"status": "committed", "document": item["doc"]}
        ctx = self.context(db, actor, item["doc"], item["revision"])
        now = self.store.now()
        require(
            now < item["expires"] and item["failures"] < 5,
            "CHALLENGE_EXPIRED",
            "Код истёк. Запросите новый код.",
            410,
        )
        require(
            canonical(ctx) == item["context"],
            "CONFLICT",
            "Данные изменились. Начните подтверждение заново.",
            409,
        )
        if not hmac.compare_digest(self.store.proof(op, code), item["verifier"]):
            db.execute("UPDATE intents SET failures=failures+1 WHERE id=?", (op,))
            # A normal return lets the enclosing transaction persist the attempt.
            return {"status": "incorrect_code", "remaining": 4 - item["failures"]}
        ctx.update(intent=op, at=now, time_source="local-system-utc")
        ctx["registry_seal"] = self.key.seal(ctx)
        doc, rev, side = item["doc"], item["revision"], ctx["side"]
        db.execute(
            "INSERT INTO signatures VALUES(?,?,?,?,?)",
            (doc, rev, side, canonical(ctx), op),
        )
        db.execute("UPDATE intents SET committed=1 WHERE id=?", (op,))
        customer = side == "customer"
        db.execute(
            "UPDATE documents SET state=? WHERE id=?",
            ("waiting" if customer else "signed", doc),
        )
        db.execute(
            "INSERT INTO outbox(id,doc,revision,kind) VALUES(?,?,?,?)",
            (token(), doc, rev, "invite" if customer else "artifact"),
        )
        self.event(db, doc, rev, actor.person, "signed:" + side)
        return {"status": "committed", "document": doc}

    def transition(self, db, actor, ident, rev, action, detail=""):
        doc = self.document(db, actor, ident)
        require(
            doc["revision"] == rev,
            "REVISION_CHANGED",
            "Откройте текущую редакцию.",
            409,
        )
        if action == "withdraw":
            self.editable(db, actor)
            require(doc["state"] in ("draft", "waiting", "changes"))
            state = "withdrawn"
        else:
            require(
                not actor.org
                and doc["state"] == "waiting"
                and action in ("comment", "decline")
            )
            require(
                len(detail) <= 2000 and (action != "comment" or detail.strip()),
                "INVALID",
                "Введите замечание до 2000 символов.",
                422,
            )
            state = "changes" if action == "comment" else "declined"
        db.execute("UPDATE documents SET state=? WHERE id=?", (state, ident))
        db.execute("UPDATE intents SET expires=0 WHERE doc=? AND committed=0", (ident,))
        db.execute("UPDATE invitations SET active=0 WHERE doc=?", (ident,))
        self.event(db, ident, rev, actor.person, action, detail)

    def revise(self, db, actor, ident, rev, checksum, transcript):
        self.editable(db, actor)
        doc = self.document(db, actor, ident)
        require(
            doc["state"] in ("changes", "draft") and rev == doc["revision"],
            "CONFLICT",
            "Текущий статус не допускает замену.",
            409,
        )
        require(
            self.version(db, ident, rev)["digest"] != checksum,
            "UNCHANGED",
            "Выберите исправленный PDF.",
            422,
        )
        self.store.read(checksum)
        db.execute(
            "INSERT INTO revisions VALUES(?,?,?,?,?)",
            (ident, rev + 1, checksum, transcript, self.store.now()),
        )
        db.execute(
            "UPDATE documents SET revision=?,state='draft' WHERE id=?", (rev + 1, ident)
        )
        db.execute("UPDATE intents SET expires=0 WHERE doc=? AND committed=0", (ident,))
        db.execute("UPDATE invitations SET active=0 WHERE doc=?", (ident,))
        self.event(db, ident, rev + 1, actor.person, "revised")

    def evidence(self, db, actor, ident, rev):
        doc = self.document(db, actor, ident)
        if not actor.org:
            found(
                db.execute(
                    "SELECT 1 FROM signatures WHERE doc=? AND revision=? AND side='customer'",
                    (ident, rev),
                ).fetchone()
            )
        revision = self.version(db, ident, rev)
        signatures = [
            json.loads(r[0])
            for r in db.execute(
                "SELECT snapshot FROM signatures WHERE doc=? AND revision=? ORDER BY side",
                (ident, rev),
            )
        ]
        require(actor.org or any(s["side"] == "customer" for s in signatures))
        return {
            "schema_version": 1,
            "environment": "local",
            "assurance": "simulated",
            "document": ident,
            "title": doc["title"],
            "revision": rev,
            "original_sha256": revision["digest"],
            "rules": doc["rules"],
            "signatures": signatures,
            "events": [
                dict(r)
                for r in db.execute(
                    "SELECT action,at,actor,detail FROM events WHERE doc=? AND revision=? ORDER BY id",
                    (ident, rev),
                )
            ],
        }
