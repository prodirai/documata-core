"""Portable evidence envelope and offline integrity check (schema 1)."""

import io
import json
import zipfile
from .store import canonical, digest


def pack(protocol, original, artifact=None):
    files = {"original.pdf": original, "protocol.json": canonical(protocol).encode()}
    if artifact:
        files["copy.pdf"] = artifact
    manifest = {
        "schema_version": 1,
        "environment": "local",
        "assurance": "simulated",
        "files": {k: digest(v) for k, v in files.items()},
    }
    files["manifest.json"] = canonical(manifest).encode()
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return out.getvalue()


def strict_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON key")
    return result


def reject_number(value):
    raise ValueError("Unsupported numeric representation")


def read_json(data):
    return json.loads(
        data,
        object_pairs_hook=strict_object,
        parse_float=reject_number,
        parse_constant=reject_number,
    )


def verify(data, trusted_key=None):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) not in (3, 4) or sum(i.file_size for i in infos) > 32 * 1024**2:
            raise ValueError("Invalid size")
        manifest = read_json(z.read("manifest.json"))
        files = manifest["files"]
        if (
            manifest["schema_version"] != 1
            or manifest["assurance"] != "simulated"
            or manifest["environment"] != "local"
        ):
            raise ValueError("Unsupported evidence schema")
        if set(files) not in (
            {"protocol.json", "original.pdf"},
            {"protocol.json", "original.pdf", "copy.pdf"},
        ) or sorted(z.namelist()) != sorted([*files, "manifest.json"]):
            raise ValueError("Invalid inventory")
        if not all(
            digest(z.read(name)) == checksum for name, checksum in files.items()
        ):
            raise ValueError("Checksum mismatch")
        protocol = read_json(z.read("protocol.json"))
        if protocol["original_sha256"] != files["original.pdf"] or any(
            s["sha256"] != protocol["original_sha256"]
            or s["revision"] != protocol["revision"]
            or s["document"] != protocol["document"]
            for s in protocol["signatures"]
        ):
            raise ValueError("Inconsistent protocol")
        if trusted_key:
            from .seal import check_signatures

            check_signatures(protocol, trusted_key)
        return protocol


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--trusted-key", type=Path)
    args = parser.parse_args()
    p = verify(args.archive.read_bytes(), args.trusted_key)
    print(
        "Checksums match. Simulated evidence. Revision",
        p["revision"],
        "signatures",
        len(p["signatures"]),
    )
    if args.trusted_key:
        print("Registry seals verified using the supplied trust anchor.")
