"""Portable evidence envelope and offline integrity check (schema 1)."""

import io
import json
import zipfile
from .store import canonical, digest


# The readable envelope keeps just the document at the archive root.
READER_PATHS = {
    "original.pdf": "Для проверки/Исходный документ.pdf",
    "copy.pdf": "Подписанный документ.pdf",
    "protocol.json": "Для проверки/Протокол.json",
    "manifest.json": "Для проверки/Состав комплекта.json",
}


REVIEW_ROOT = "С отметкой заказчика.pdf"
REVIEW_ARCHIVE = "Для проверки/" + REVIEW_ROOT


def pack(protocol, original, artifact=None, *, registry_key=None, reader_layout=False, review=None):
    if reader_layout and not registry_key:
        raise ValueError("Reader envelopes require an inventory seal")
    names = READER_PATHS if reader_layout else {}
    files = {"original.pdf": original, "protocol.json": canonical(protocol).encode()}
    if review is not None:
        if not reader_layout or digest(review) != protocol["review_manifest"]["review_sha256"]:
            raise ValueError("Invalid review copy")
        files[REVIEW_ARCHIVE if artifact else REVIEW_ROOT] = review
    if reader_layout and not artifact and review is None:
        names = {**names, "original.pdf": "Исходный документ.pdf"}
    if artifact:
        files["copy.pdf"] = artifact
    files = {names.get(k, k): v for k, v in files.items()}
    manifest = {
        "schema_version": 4 if review is not None else 3 if reader_layout else (2 if registry_key else 1),
        "environment": "local",
        "assurance": "simulated",
        "files": {k: digest(v) for k, v in files.items()},
    }
    if registry_key:
        manifest["registry_seal"] = registry_key.seal(
            {"purpose": "documata.export-inventory", "manifest": manifest}
        )
    files[names.get("manifest.json", "manifest.json")] = canonical(manifest).encode()
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


def verify(data, trusted_key=None, *, require_envelope_seal=False):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        infos = z.infolist()
        if len(infos) not in (3, 4, 5) or sum(i.file_size for i in infos) > 48 * 1024**2:
            raise ValueError("Invalid size")
        names = READER_PATHS if READER_PATHS["manifest.json"] in z.namelist() else {}
        manifest_name = names.get("manifest.json", "manifest.json")
        manifest = read_json(z.read(manifest_name))
        files = manifest["files"]
        if (
            manifest["schema_version"] not in ((3, 4) if names else (1, 2))
            or manifest["assurance"] != "simulated"
            or manifest["environment"] != "local"
        ):
            raise ValueError("Unsupported evidence schema")
        if require_envelope_seal and (
            not trusted_key or manifest["schema_version"] not in (2, 3, 4)
        ):
            raise ValueError("A sealed inventory and a separate trust key are required")
        if manifest["schema_version"] in (2, 3, 4):
            from .seal import check_seal

            seal = manifest.pop("registry_seal", None)
            if not isinstance(seal, dict):
                raise ValueError("Missing inventory seal")
            if trusted_key:
                check_seal(
                    {"purpose": "documata.export-inventory", "manifest": manifest},
                    seal,
                    trusted_key,
                )
        protocol_name = names.get("protocol.json", "protocol.json")
        original_name = names.get("original.pdf", "original.pdf")
        has_review = manifest["schema_version"] == 4
        if names and names["copy.pdf"] not in files and not has_review:
            original_name = "Исходный документ.pdf"
        required = {protocol_name, original_name}
        if has_review:
            review_name = REVIEW_ARCHIVE if names["copy.pdf"] in files else REVIEW_ROOT
            required.add(review_name)
        if set(files) not in (required, required | {names.get("copy.pdf", "copy.pdf")}) or sorted(z.namelist()) != sorted([*files, manifest_name]):
            raise ValueError("Invalid inventory")
        if not all(
            digest(z.read(name)) == checksum for name, checksum in files.items()
        ):
            raise ValueError("Checksum mismatch")
        protocol = read_json(z.read(protocol_name))
        if protocol["original_sha256"] != files[original_name] or any(
            s["sha256"] != protocol["original_sha256"]
            or s["revision"] != protocol["revision"]
            or s["document"] != protocol["document"]
            for s in protocol["signatures"]
        ):
            raise ValueError("Inconsistent protocol")
        if has_review:
            review = protocol.get("review_manifest", {})
            customer = next((s for s in protocol["signatures"] if s["side"] == "customer"), None)
            if (
                not customer or review.get("customer_intent") != customer["intent"]
                or review.get("review_sha256") != files[review_name]
                or review.get("source_sha256") != files[original_name]
                or review.get("document") != protocol["document"]
                or review.get("revision") != protocol["revision"]
                or any(s["side"] == "performer" and (
                    s.get("review_manifest") != review or s.get("viewed_sha256") != files[review_name]
                ) for s in protocol["signatures"])
            ):
                raise ValueError("Inconsistent review manifest")
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
    parser.add_argument(
        "--require-envelope-seal",
        action="store_true",
        help="Require a sealed inventory and a separately trusted key",
    )
    args = parser.parse_args()
    p = verify(
        args.archive.read_bytes(),
        args.trusted_key,
        require_envelope_seal=args.require_envelope_seal,
    )
    print(
        "Checksums match. Simulated evidence. Revision",
        p["revision"],
        "signatures",
        len(p["signatures"]),
    )
    if args.trusted_key:
        print("Snapshot seals verified using the supplied trust anchor.")
    if args.require_envelope_seal:
        print("Sealed export inventory verified.")
