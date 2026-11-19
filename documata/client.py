"""Minimal read-only client for a local authenticated v1 service."""

import argparse
import getpass
from http.client import HTTPConnection
from http.cookies import SimpleCookie
import json
from pathlib import Path
from urllib.parse import quote


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=4196)
    parser.add_argument("--login", required=True)
    parser.add_argument("--document")
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--export-to", type=Path)
    args = parser.parse_args()
    origin = f"http://127.0.0.1:{args.port}"
    cookie = ""

    def request(route, payload=None):
        nonlocal cookie
        client = HTTPConnection("127.0.0.1", args.port, timeout=15)
        try:
            client.request(
                "POST" if payload is not None else "GET",
                "/v1/" + route,
                body=json.dumps(payload) if payload is not None else None,
                headers={
                    "Origin": origin,
                    "Content-Type": "application/json",
                    "X-Documata": "local",
                    "Cookie": cookie,
                },
            )
            response = client.getresponse()
            data = response.read()
            if response.status >= 400:
                raise SystemExit(json.loads(data)["error"]["message"])
            if response.getheader("Set-Cookie"):
                parsed = SimpleCookie(response.getheader("Set-Cookie"))
                cookie = "dm_session=" + parsed["dm_session"].value
            return (
                json.loads(data)
                if response.getheader("Content-Type", "").startswith("application/json")
                else data
            )
        finally:
            client.close()

    login = request(
        "login", {"login": args.login, "password": getpass.getpass("Password: ")}
    )
    if login["status"] != "challenge":
        raise SystemExit(login["status"])
    auth = request(
        "login/confirm",
        {"operation": login["operation"], "code": getpass.getpass("Login code: ")},
    )
    if auth["status"] != "ok":
        raise SystemExit(auth["status"])
    try:
        if args.export_to and args.document:
            archive = request(
                "documents/"
                + quote(args.document, safe="")
                + "/"
                + str(args.revision)
                + "/export"
            )
            with args.export_to.open("xb") as out:
                out.write(archive)
        else:
            for row in request("documents"):
                print(row["id"], row["revision"], row["state"], row["title"])
    finally:
        request("logout", {})


if __name__ == "__main__":
    main()
