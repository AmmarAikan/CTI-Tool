#!/usr/bin/env python3
"""Bounded interactive validation of the local Central Dark Web control surface.

This script is intentionally inert until invoked by an operator. It never prints
response bodies, URLs, tokens, keywords, or advisory content.
"""
from __future__ import annotations

import getpass
import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ISOLATED_FRONTEND_PORT = 19080


def validated_base_url(value: str) -> str:
    """Validate a Central base URL without performing DNS or network access."""
    candidate=value.strip()
    try: parsed=urlsplit(candidate)
    except ValueError as exc: raise ValueError("invalid target URL") from exc
    if parsed.scheme not in {"http","https"} or not parsed.hostname:
        raise ValueError("invalid target URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("embedded credentials are forbidden")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("target must not include a path, query, or fragment")
    try: port=parsed.port
    except ValueError as exc: raise ValueError("invalid target port") from exc
    loopback=parsed.hostname in {"127.0.0.1","localhost"}
    if parsed.scheme=="http" and (not loopback or port!=ISOLATED_FRONTEND_PORT):
        raise ValueError("plain HTTP is restricted to the isolated frontend proxy")
    host=f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme}://{host}"+(f":{port}" if port is not None else "")


def parser() -> argparse.ArgumentParser:
    value=argparse.ArgumentParser(description="Interactively validate the bounded Dark Web control contract.")
    value.add_argument("--base-url",help="Central base URL; HTTP is allowed only for localhost:19080.")
    return value


def main(argv: list[str] | None=None) -> int:
    args=parser().parse_args(argv)
    raw=args.base_url if args.base_url is not None else input("Central base URL: ")
    try:base=validated_base_url(raw)
    except ValueError:
        print("rejected: target URL is not permitted");return 2
    token=getpass.getpass("Bearer token: ").strip()
    if not token or len(token)>4096:print("rejected: invalid credential length");return 2
    request=urllib.request.Request(base+"/api/v1/dark-web/watches",headers={"Authorization":"Bearer "+token,"Accept":"application/json"})
    try:
        with urllib.request.urlopen(request,timeout=10) as response:
            if response.status!=200:print("failed: unexpected status");return 1
            body=response.read(262145)
            if len(body)>262144:print("failed: response exceeded bound");return 1
            value=json.loads(body)
            if not isinstance(value,dict) or value.get("schema_version")!="1.0" or not isinstance(value.get("items"),list) or len(value["items"])>100:
                print("failed: response contract rejected");return 1
    except (urllib.error.URLError,TimeoutError,ValueError,json.JSONDecodeError) as exc:
        print("failed: "+type(exc).__name__);return 1
    print("passed: bounded Dark Web watch contract")
    return 0


if __name__=="__main__":sys.exit(main())
