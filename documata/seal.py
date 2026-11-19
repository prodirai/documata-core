"""Offline P-256 registry attestations, independent of the signer's challenge."""

import base64
from pathlib import Path
import subprocess
import tempfile
from .store import canonical, digest


def openssl(args, data=b""):
    return subprocess.run(
        ["openssl", *args],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=5,
    ).stdout


class RegistryKey:
    def __init__(self, store):
        self.path = store.root / "registry.signing"
        if not self.path.is_file():
            key = openssl(
                ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
            )
            store.install(self.path, key)
        self.public = openssl(["pkey", "-in", str(self.path), "-pubout"])
        self.id = digest(self.public)
        store.install(store.root / "registry.public", self.public)

    def seal(self, snapshot):
        data = canonical(snapshot).encode()
        sig = openssl(["dgst", "-sha256", "-sign", str(self.path)], data)
        return {
            "schema_version": 1,
            "algorithm": "ECDSA-P256-SHA256",
            "key_id": self.id,
            "value": base64.b64encode(sig).decode(),
        }


def check_seal(value, seal, trusted_key):
    key = Path(trusted_key)
    if (
        not isinstance(seal, dict)
        or seal.get("key_id") != digest(key.read_bytes())
        or seal.get("algorithm") != "ECDSA-P256-SHA256"
        or seal.get("schema_version") != 1
    ):
        raise ValueError("Missing or untrusted registry seal")
    with tempfile.NamedTemporaryFile() as f:
        f.write(base64.b64decode(seal["value"], validate=True))
        f.flush()
        try:
            openssl(
                ["dgst", "-sha256", "-verify", str(key), "-signature", f.name],
                canonical(value).encode(),
            )
        except subprocess.CalledProcessError as error:
            raise ValueError("Invalid registry seal") from error


def check_signatures(protocol, trusted_key):
    for item in protocol["signatures"]:
        snapshot = dict(item)
        seal = snapshot.pop("registry_seal", None)
        check_seal(snapshot, seal, trusted_key)
