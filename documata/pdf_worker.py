"""Disposable PDF process. Reads stdin, never receives registry paths or credentials."""

import base64
import ctypes
import ctypes.util
import errno
import io
import json
import resource
import sys
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    DecodedStreamObject,
    NameObject,
)


def restrict():
    for limit, value in (
        (resource.RLIMIT_CPU, 5),
        (resource.RLIMIT_FSIZE, 0),
        (resource.RLIMIT_CORE, 0),
    ):
        resource.setrlimit(limit, (value, value))
    if sys.platform == "darwin":
        lib = ctypes.CDLL("/usr/lib/libsandbox.dylib")
        error = ctypes.c_char_p()
        profile = b"(version 1)(allow default)(deny network*)(deny file-read-data)(deny file-write*)(deny process-exec)(deny process-fork)"
        if lib.sandbox_init(profile, 0, ctypes.byref(error)) != 0:
            raise RuntimeError("sandbox")
    elif sys.platform == "linux":
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024**2, 384 * 1024**2))
        lib = ctypes.CDLL("libseccomp.so.2")
        lib.seccomp_init.restype = ctypes.c_void_p
        policy = ctypes.c_void_p(lib.seccomp_init(0x00050000 | errno.EPERM))
        for name in (
            "read",
            "write",
            "close",
            "fstat",
            "newfstatat",
            "lseek",
            "brk",
            "mmap",
            "mremap",
            "mprotect",
            "munmap",
            "madvise",
            "futex",
            "clock_gettime",
            "getrandom",
            "getpid",
            "gettid",
            "rt_sigaction",
            "rt_sigprocmask",
            "rt_sigreturn",
            "exit",
            "exit_group",
            "ioctl",
            "getrusage",
            "sched_yield",
        ):
            nr = lib.seccomp_syscall_resolve_name(name.encode())
            if nr >= 0 and lib.seccomp_rule_add(policy, 0x7FFF0000, nr, 0):
                raise RuntimeError("seccomp")
        if lib.seccomp_load(policy):
            raise RuntimeError("seccomp")
    else:
        raise RuntimeError("Unsupported PDF isolation platform")


def inspect(reader):
    forbidden = {
        "/OpenAction",
        "/AA",
        "/JS",
        "/JavaScript",
        "/AcroForm",
        "/EmbeddedFiles",
        "/EmbeddedFile",
        "/Filespec",
        "/Launch",
        "/RichMedia",
        "/Sig",
        "/XFA",
        "/URI",
        "/GoToR",
        "/SubmitForm",
        "/Annots",
        "/Encrypt",
        "/EF",
    }
    if reader.is_encrypted or not 1 <= len(reader.pages) <= 20:
        raise ValueError()
    visited = set()
    pending = [reader.trailer]
    while pending:
        obj = pending.pop()
        if isinstance(obj, IndirectObject):
            key = (obj.idnum, obj.generation)
            if key in visited:
                continue
            visited.add(key)
            if len(visited) > 50000:
                raise ValueError()
            obj = obj.get_object()
        if isinstance(obj, DictionaryObject):
            if any(k in forbidden for k in obj):
                raise ValueError()
            pending.extend(obj.values())
        elif isinstance(obj, ArrayObject):
            pending.extend(obj)
        elif isinstance(obj, NameObject) and obj in forbidden:
            raise ValueError()
    return "\n".join(page.extract_text() or "" for page in reader.pages)[:150000]


def marked(reader, label):
    # Strict ASCII identifiers supplied by the registry, no user-authored PDF operators.
    import re

    if not re.fullmatch(r"[a-zA-Z0-9 _.:/\-\n]{1,1800}", label):
        raise ValueError()
    writer = PdfWriter()
    writer.append(reader)
    page = writer.add_blank_page(width=595, height=842)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})}
    )
    stream = DecodedStreamObject()
    body = (
        "BT /F1 10 Tf 44 784 Td 18 TL "
        + " ".join("(" + line + ") Tj T*" for line in label.splitlines())
        + " ET"
    )
    stream.set_data(body.encode())
    page[NameObject("/Contents")] = writer._add_object(stream)
    output = io.BytesIO()
    writer.write(output)
    return base64.b64encode(output.getvalue()).decode()


if __name__ == "__main__":
    # Load codecs and parser support before removing filesystem access.
    import encodings.utf_16_be, encodings.utf_16_le, encodings.cp1252, encodings.latin_1, encodings.utf_8_sig
    import importlib

    for module in (
        "pypdf.filters",
        "pypdf._cmap",
        "pypdf._page",
        "pypdf._text_extraction",
        "uuid",
        "secrets",
        "unicodedata",
    ):
        importlib.import_module(module)
    import codecs, encodings.aliases

    for name in set(encodings.aliases.aliases.values()) | {"charmap"}:
        try:
            codecs.lookup(name)
        except LookupError:
            pass
    restrict()
    try:
        appendix = None
        if len(sys.argv) == 3 and sys.argv[1] == "--append-page":
            size = int(sys.argv[2])
            if not 0 < size <= 10485760:
                raise ValueError()
            data = sys.stdin.buffer.read(size)
            appendix = sys.stdin.buffer.read(1500001)
            if len(appendix) > 1500000:
                raise ValueError()
        else:
            data = sys.stdin.buffer.read(10485761)
        if len(data) > 10485760 or not data.startswith(b"%PDF-"):
            raise ValueError()
        reader = PdfReader(io.BytesIO(data), strict=True)
        transcript = inspect(reader)
        result = {"text": transcript, "pages": len(reader.pages)}
        if appendix is not None:
            note = PdfReader(io.BytesIO(appendix), strict=True)
            if len(note.pages) != 1:
                raise ValueError()
            writer = PdfWriter()
            writer.append(reader)
            writer.add_page(note.pages[0])
            output = io.BytesIO()
            writer.write(output)
            result["artifact"] = base64.b64encode(output.getvalue()).decode()
        elif len(sys.argv) > 1:
            result["artifact"] = marked(reader, sys.argv[1])
        print(json.dumps(result, ensure_ascii=True))
    except Exception:
        sys.exit(2)
