from __future__ import annotations

import hashlib
import html
import os
import re
import sqlite3
import threading
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from backend.app.pipeline.ingestion.external.dark_web_connector import (
    DarkWebRequestError, DarkWebSource, TorHttpClient, TorUnavailableError,
)


class WatchValidationError(ValueError): pass
class WatchNotFound(LookupError): pass
class WatchConflict(RuntimeError): pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_keyword(value: str) -> str:
    value = " ".join(unicodedata.normalize("NFKC", value).split())
    if not 2 <= len(value) <= 100 or any(unicodedata.category(ch) == "Cc" for ch in value):
        raise WatchValidationError("keyword_length_or_control")
    lowered = value.casefold()
    if (re.search(r"https?://|\b\S*\.onion\b|[<>{}\[\]`]|(?:^|\s)(?:and|or|not|site|inurl|intitle):?\b", lowered)
            or any(ch in value for ch in ('"', "'", "\\", "|", "&"))):
        raise WatchValidationError("keyword_syntax_not_allowed")
    return value


class SQLiteDarkWebWatchStore:
    VERSION = 1
    def __init__(self, path: Path, *, max_watches: int = 100, max_results_per_watch: int = 1000) -> None:
        self.path, self.max_watches, self.max_results = path, max_watches, max_results_per_watch
        self._prepare(); self._schema()

    def _prepare(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink() or self.path.parent.is_symlink(): raise RuntimeError("watch database path is unsafe")
        resolved_parent = self.path.parent.resolve(); resolved = self.path.resolve(strict=False)
        if resolved.parent != resolved_parent or (self.path.exists() and not self.path.is_file()): raise RuntimeError("watch database path is unsafe")
        if self.path.exists(): os.chmod(self.path, 0o600)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5); db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA journal_mode=WAL")
        if self.path.exists(): os.chmod(self.path, 0o600)
        return db

    def _schema(self) -> None:
        with self._connect() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > self.VERSION: raise RuntimeError("watch database schema is newer than this service")
            db.executescript("""
              CREATE TABLE IF NOT EXISTS watches(watch_id TEXT PRIMARY KEY, keyword TEXT NOT NULL, keyword_folded TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL CHECK(enabled IN(0,1)), created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                last_scan_at TEXT, last_success_at TEXT, result_count INTEGER NOT NULL DEFAULT 0,
                new_result_count INTEGER NOT NULL DEFAULT 0, checkpoint_hash TEXT);
              CREATE TABLE IF NOT EXISTS results(result_id TEXT PRIMARY KEY, watch_id TEXT NOT NULL REFERENCES watches(watch_id),
                canonical_hash TEXT NOT NULL, content_sha256 TEXT NOT NULL, onion_reference TEXT NOT NULL,
                title TEXT NOT NULL, excerpt TEXT NOT NULL, provider TEXT NOT NULL, first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL, classification_label TEXT, classification_confidence REAL,
                privacy_status TEXT NOT NULL, review_reasons TEXT NOT NULL, UNIQUE(watch_id,canonical_hash));
              PRAGMA user_version=1;
            """)

    def list_watches(self) -> list[dict[str, Any]]:
        with self._connect() as db: rows=db.execute("SELECT * FROM watches ORDER BY created_at DESC LIMIT ?",(self.max_watches,)).fetchall()
        return [self._watch(r) for r in rows]

    def create(self, keyword: str) -> dict[str, Any]:
        normalized=normalize_keyword(keyword); now=utc_now(); watch_id="dww-"+uuid.uuid4().hex
        try:
            with self._connect() as db:
                if db.execute("SELECT COUNT(*) FROM watches").fetchone()[0] >= self.max_watches: raise WatchConflict("watch_limit")
                db.execute("INSERT INTO watches(watch_id,keyword,keyword_folded,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                           (watch_id,normalized,normalized.casefold(),1,now,now))
        except sqlite3.IntegrityError as exc: raise WatchConflict("duplicate_watch") from exc
        return self.get(watch_id)

    def get(self, watch_id: str) -> dict[str, Any]:
        with self._connect() as db: row=db.execute("SELECT * FROM watches WHERE watch_id=?",(watch_id,)).fetchone()
        if row is None: raise WatchNotFound()
        return self._watch(row)

    def set_enabled(self, watch_id: str, enabled: bool) -> dict[str, Any]:
        with self._connect() as db:
            changed=db.execute("UPDATE watches SET enabled=?,updated_at=? WHERE watch_id=?",(int(enabled),utc_now(),watch_id)).rowcount
        if not changed: raise WatchNotFound()
        return self.get(watch_id)

    def results(self, watch_id: str, limit: int, offset: int) -> dict[str, Any]:
        self.get(watch_id)
        with self._connect() as db:
            total=db.execute("SELECT COUNT(*) FROM results WHERE watch_id=?",(watch_id,)).fetchone()[0]
            rows=db.execute("SELECT * FROM results WHERE watch_id=? ORDER BY first_seen_at DESC,result_id DESC LIMIT ? OFFSET ?",(watch_id,limit,offset)).fetchall()
        return {"items":[dict(r) for r in rows],"total":total,"limit":limit,"offset":offset}

    def commit_scan(self, watch_id: str, candidates: list[dict[str, Any]], *, partial: bool) -> dict[str, int]:
        now=utc_now(); new=0
        with self._connect() as db:
            watch=db.execute("SELECT checkpoint_hash FROM watches WHERE watch_id=? AND enabled=1",(watch_id,)).fetchone()
            if watch is None: raise WatchNotFound()
            for item in candidates:
                old=db.execute("SELECT result_id FROM results WHERE watch_id=? AND canonical_hash=?",(watch_id,item["canonical_hash"])).fetchone()
                if old: db.execute("UPDATE results SET last_seen_at=? WHERE result_id=?",(now,old[0]))
                else:
                    new+=1; db.execute("INSERT INTO results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(item["result_id"],watch_id,item["canonical_hash"],item["content_sha256"],item["onion_reference"],item["title"],item["excerpt"],item["provider"],now,now,item.get("classification_label"),item.get("classification_confidence"),item["privacy_status"],",".join(item["review_reasons"])))
            db.execute("DELETE FROM results WHERE watch_id=? AND result_id NOT IN (SELECT result_id FROM results WHERE watch_id=? ORDER BY last_seen_at DESC LIMIT ?)",(watch_id,watch_id,self.max_results))
            total=db.execute("SELECT COUNT(*) FROM results WHERE watch_id=?",(watch_id,)).fetchone()[0]
            checkpoint=hashlib.sha256("\n".join(sorted(x["canonical_hash"] for x in candidates)).encode()).hexdigest()
            db.execute("UPDATE watches SET last_scan_at=?,last_success_at=?,result_count=?,new_result_count=?,checkpoint_hash=?,updated_at=? WHERE watch_id=?",(now,now,total,new,checkpoint,now,watch_id))
        return {"result_count":total,"new_result_count":new,"partial":int(partial)}

    @staticmethod
    def _watch(r): return {k:r[k] for k in r.keys() if k != "keyword_folded"} | {"enabled":bool(r["enabled"])}


class DarkWebWatchScanner:
    def __init__(self, sources: Iterable[DarkWebSource], client: TorHttpClient, *, max_pages: int = 20) -> None:
        self.sources=tuple(s for s in sources if s.enabled); self.client=client; self.max_pages=max(1,min(max_pages,20))

    def scan(self, keyword: str) -> tuple[list[dict[str, Any]], bool]:
        matches=[]; failures=successes=0
        for source in self.sources:
            urls=[source.url]; seen=set()
            while urls and len(seen)<min(source.max_items,self.max_pages):
                url=urls.pop(0)
                if url in seen or not source.allows(url): continue
                seen.add(url)
                try: response=self.client.get(source,url)
                except (TorUnavailableError,DarkWebRequestError): failures+=1; continue
                if response.status_code != 200: failures+=1; continue
                successes+=1; soup=BeautifulSoup(response.content,"html.parser")
                for tag in soup(["script","style","form","nav","header","footer"]): tag.decompose()
                text=" ".join(soup.get_text(" ",strip=True).split()); title=_safe_text(" ".join((soup.title.get_text(" ",strip=True) if soup.title else source.name).split()),200)
                folded=text.casefold(); needle=keyword.casefold(); pos=folded.find(needle)
                if pos>=0:
                    excerpt=_safe_text(text[max(0,pos-100):min(len(text),pos+len(keyword)+100)],240)
                    ref=hashlib.sha256(url.encode()).hexdigest(); content=hashlib.sha256(text.encode()).hexdigest()
                    matches.append({"result_id":"dwr-"+hashlib.sha256((ref+content).encode()).hexdigest()[:32],"canonical_hash":ref,"content_sha256":content,"onion_reference":"onion-ref:"+ref[:12],"title":html.unescape(title),"excerpt":excerpt,"provider":source.name[:100],"privacy_status":"reviewed","review_reasons":[]})
                for a in soup.find_all("a",href=True):
                    child=urljoin(url,str(a["href"]));
                    if source.allows(child) and child not in seen and len(urls)+len(seen)<self.max_pages: urls.append(child)
        if successes == 0: raise TorUnavailableError("dark web scan unavailable")
        return matches, failures>0


class DarkWebWatchService:
    def __init__(self, store: SQLiteDarkWebWatchStore, scanner: DarkWebWatchScanner): self.store,self.scanner,self._active,self._lock=store,scanner,set(),threading.Lock()
    def scan(self, watch_id: str) -> dict[str, Any]:
        with self._lock:
            if watch_id in self._active: raise WatchConflict("scan_active")
            self._active.add(watch_id)
        try:
            watch=self.store.get(watch_id)
            if not watch["enabled"]: raise WatchConflict("watch_disabled")
            matches,partial=self.scanner.scan(watch["keyword"])
            counts=self.store.commit_scan(watch_id,matches,partial=partial)
            return {"status":"partial" if partial else "completed","accepted_records":counts["result_count"],
                    "review_records":0,"rejected_records":0,"skipped_records":counts["result_count"]-counts["new_result_count"],"error_count":int(partial)}
        finally:
            with self._lock: self._active.discard(watch_id)

def _safe_text(value: str, maximum: int) -> str:
    value=re.sub(r"https?://\S+|\b\S*\.onion\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:token|password|secret|authorization|cookie|api[_-]?key)\s*[=:]\s*\S+","[redacted]",value,flags=re.I)
    return " ".join(value.split())[:maximum]
