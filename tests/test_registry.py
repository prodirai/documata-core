import concurrent.futures
import io
import tempfile
import unittest
from pypdf import PdfWriter
from documata.store import Store, Problem, digest
from documata.registry import Actor, Registry, RULES
from documata.pdf import inspect_pdf
from documata.export import pack, verify


class RegistryTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.now = 100000
        self.store = Store(tmp.name, lambda: self.now)
        self.reg = Registry(self.store)
        self.customer = Actor("alice", "o", "s1")
        self.performer = Actor("bob", None, "s2")
        w = PdfWriter()
        w.add_blank_page(320, 400)
        b = io.BytesIO()
        w.write(b)
        self.pdf = b.getvalue()
        self.sha = self.store.put(self.pdf)
        with self.store.transaction() as db:
            db.execute("INSERT INTO organizations VALUES('o','Example')")
            for p in ("alice", "bob", "eva"):
                db.execute(
                    "INSERT INTO subjects VALUES(?,?,?,'id-op','phone-op',0)",
                    (p, p, "synthetic"),
                )
            db.execute("INSERT INTO members VALUES('o','alice','owner',999999)")
            self.doc = self.reg.create(
                db, self.customer, "Example", "bob", "alice", self.sha, ""
            )

    def intent(self, a=None):
        codes = []
        with self.store.transaction() as db:
            op = self.reg.start(
                db,
                a or self.customer,
                self.doc,
                1,
                self.sha,
                digest(RULES.encode()),
                True,
                lambda op, c: codes.append(c),
            )
        return op, codes[0]

    def confirm(self, op, code, a=None):
        with self.store.transaction() as db:
            return self.reg.confirm(db, a or self.customer, op, code)

    def test_cycle_and_concurrent_replay(self):
        op, code = self.intent()
        with concurrent.futures.ThreadPoolExecutor(3) as pool:
            results = list(pool.map(lambda _: self.confirm(op, code), range(3)))
        self.assertTrue(all(r["status"] == "committed" for r in results))
        op, code = self.intent(self.performer)
        self.confirm(op, code, self.performer)
        with self.store.transaction() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM signatures").fetchone()[0], 2
            )
            self.assertEqual(db.execute("SELECT count(*) FROM outbox").fetchone()[0], 2)
            e = self.reg.evidence(db, self.performer, self.doc, 1)
            self.assertEqual(
                verify(pack(e, self.pdf), self.store.root / "registry.public"), e
            )
            e["signatures"][0]["name"] = "altered"
            with self.assertRaises(ValueError):
                verify(pack(e, self.pdf), self.store.root / "registry.public")
            with self.assertRaises(Problem):
                self.reg.revise(db, self.customer, self.doc, 1, self.sha, "")

    def test_access_and_revoke(self):
        with self.store.transaction() as db:
            for a in [
                self.performer,
                Actor("eva", "o", "s3"),
                Actor("alice", "other", "s1"),
            ]:
                self.assertEqual(self.reg.visible(db, a), [])
                with self.assertRaises(Problem):
                    self.reg.document(db, a, self.doc)
        op, code = self.intent()
        with self.store.transaction() as db:
            db.execute("UPDATE members SET authority=0")
        with self.assertRaises(Problem):
            self.confirm(op, code)

    def test_wrong_code_and_expiry(self):
        op, code = self.intent()
        with self.assertRaises(Problem):
            self.confirm(op, code, Actor("alice", "o", "new"))
        for _ in range(5):
            self.assertEqual(self.confirm(op, "invalid")["status"], "incorrect_code")
        with self.assertRaises(Problem):
            self.confirm(op, code)
        self.now += 61
        op, code = self.intent()
        self.now += 300
        with self.assertRaises(Problem):
            self.confirm(op, code)

    def test_revision_and_snapshot(self):
        self.confirm(*self.intent())
        op, code = self.intent(self.performer)
        with self.store.transaction() as db:
            self.reg.transition(
                db, self.performer, self.doc, 1, "comment", "Amend the date"
            )
            self.reg.revise(
                db, self.customer, self.doc, 1, self.store.put(self.pdf + b"\n"), ""
            )
        with self.assertRaises(Problem):
            self.confirm(op, code, self.performer)
        with self.store.transaction() as db:
            db.execute("UPDATE subjects SET name='new name' WHERE id='alice'")
            self.assertEqual(
                self.reg.evidence(db, self.customer, self.doc, 1)["signatures"][0][
                    "name"
                ],
                "alice",
            )

    def test_integrity_failure_blocks_commit(self):
        op, code = self.intent()
        (self.store.blobs / self.sha).unlink()
        with self.assertRaises(Problem):
            self.confirm(op, code)
        with self.store.transaction() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM signatures").fetchone()[0], 0
            )

    def test_worker(self):
        self.assertEqual(inspect_pdf(self.pdf)["pages"], 1)
        self.assertIn("artifact", inspect_pdf(self.pdf, "Documata / simulation"))
        with self.assertRaises(Problem):
            inspect_pdf(b"not a PDF")
        writer = PdfWriter()
        for _ in range(21):
            writer.add_blank_page(30, 40)
        buf = io.BytesIO()
        writer.write(buf)
        with self.assertRaises(Problem):
            inspect_pdf(buf.getvalue())
