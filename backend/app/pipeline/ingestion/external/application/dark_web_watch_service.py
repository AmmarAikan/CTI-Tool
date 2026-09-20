from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sqlite3
import stat
import threading
import secrets
import unicodedata
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
    VERSION = 4
    ALLOWED_INTERVALS = frozenset({3600, 21600, 43200, 86400})
    def __init__(self, path: Path, *, max_watches: int = 100, max_results_per_watch: int = 1000) -> None:
        self.path, self.max_watches, self.max_results = path, max_watches, max_results_per_watch
        self._prepare(); self._schema()

    def _prepare(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.is_symlink() or self.path.parent.is_symlink(): raise RuntimeError("watch database path is unsafe")
        resolved_parent = self.path.parent.resolve(); resolved = self.path.resolve(strict=False)
        if resolved.parent != resolved_parent or (self.path.exists() and not self.path.is_file()): raise RuntimeError("watch database path is unsafe")
        if self.path.exists():
            details=self.path.stat()
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077: raise RuntimeError("watch database permissions are unsafe")
        else:
            descriptor=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(descriptor)

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
            """)
            watch_columns={row[1] for row in db.execute("PRAGMA table_info(watches)")}
            for name,definition in (("keywords_json","TEXT"),("match_mode","TEXT NOT NULL DEFAULT 'any'"),("provider_id","TEXT"),("scan_interval_seconds","INTEGER NOT NULL DEFAULT 3600")):
                if name not in watch_columns: db.execute(f"ALTER TABLE watches ADD COLUMN {name} {definition}")
            for name,definition in (("schedule_enabled","INTEGER NOT NULL DEFAULT 0"),("next_run_at","TEXT"),
                    ("last_scheduled_run_at","TEXT"),("last_attempt_at","TEXT"),("scheduler_occurrence_id","TEXT"),
                    ("schedule_failure_category","TEXT")):
                if name not in watch_columns: db.execute(f"ALTER TABLE watches ADD COLUMN {name} {definition}")
            result_columns={row[1] for row in db.execute("PRAGMA table_info(results)")}
            for name,definition in (("matched_keywords","TEXT NOT NULL DEFAULT ''"),("collected_at","TEXT"),("protected_url","TEXT")):
                if name not in result_columns: db.execute(f"ALTER TABLE results ADD COLUMN {name} {definition}")
            db.executescript("""
              CREATE TABLE IF NOT EXISTS discovered_sources(source_id TEXT PRIMARY KEY, watch_id TEXT NOT NULL REFERENCES watches(watch_id),
                onion_reference TEXT NOT NULL, protected_url TEXT NOT NULL, enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(watch_id,onion_reference));
              CREATE TABLE IF NOT EXISTS alerts(alert_id TEXT PRIMARY KEY,watch_id TEXT NOT NULL REFERENCES watches(watch_id),
                result_id TEXT NOT NULL REFERENCES results(result_id),onion_reference TEXT NOT NULL,content_sha256 TEXT NOT NULL,
                alert_type TEXT NOT NULL CHECK(alert_type IN('new_match','content_changed')),matched_keywords TEXT NOT NULL,
                created_at TEXT NOT NULL,read_at TEXT,UNIQUE(watch_id,result_id,content_sha256));
              CREATE TABLE IF NOT EXISTS scheduler_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),lease_owner TEXT,lease_expires_at TEXT);
              INSERT OR IGNORE INTO scheduler_state(singleton) VALUES(1);
              CREATE TABLE IF NOT EXISTS schedule_occurrences(occurrence_id TEXT PRIMARY KEY,watch_id TEXT NOT NULL REFERENCES watches(watch_id),
                due_at TEXT NOT NULL,claimed_at TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN('claimed','submitted','completed','failed')),
                job_id TEXT,UNIQUE(watch_id,due_at));
            """)
            discovered_columns={row[1] for row in db.execute("PRAGMA table_info(discovered_sources)")}
            if "archived_at" not in discovered_columns:db.execute("ALTER TABLE discovered_sources ADD COLUMN archived_at TEXT")
            db.execute("PRAGMA user_version=4")

    def list_watches(self) -> list[dict[str, Any]]:
        with self._connect() as db: rows=db.execute("SELECT * FROM watches ORDER BY created_at DESC LIMIT ?",(self.max_watches,)).fetchall()
        return [self._watch(r) for r in rows]

    def create(self, keyword: str) -> dict[str, Any]:
        return self.create_advanced([keyword], "any", None, 3600)

    def create_advanced(self, keywords: list[str], match_mode: str, provider_id: str | None, scan_interval_seconds: int) -> dict[str, Any]:
        from backend.app.pipeline.ingestion.external.application.dark_web_discovery import normalize_keywords
        normalized_keywords=normalize_keywords(keywords)
        if match_mode not in {"any","all"} or provider_id is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",provider_id): raise WatchValidationError("watch_options")
        if not 300 <= scan_interval_seconds <= 604800: raise WatchValidationError("scan_interval")
        normalized=normalized_keywords[0]; now=utc_now(); watch_id="dww-"+uuid.uuid4().hex
        try:
            with self._connect() as db:
                if db.execute("SELECT COUNT(*) FROM watches").fetchone()[0] >= self.max_watches: raise WatchConflict("watch_limit")
                folded="\0".join(item.casefold() for item in normalized_keywords)
                db.execute("INSERT INTO watches(watch_id,keyword,keyword_folded,enabled,created_at,updated_at,keywords_json,match_mode,provider_id,scan_interval_seconds) VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (watch_id,normalized,folded,1,now,now,json.dumps(normalized_keywords,ensure_ascii=False),match_mode,provider_id,scan_interval_seconds))
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

    def promote(self, watch_id: str, result_id: str, expected_content_sha256: str) -> dict[str, Any]:
        now=utc_now()
        with self._connect() as db:
            row=db.execute("SELECT onion_reference,protected_url,content_sha256 FROM results WHERE watch_id=? AND result_id=?",(watch_id,result_id)).fetchone()
            if row is None or not row["protected_url"]: raise WatchNotFound()
            if row["content_sha256"] != expected_content_sha256: raise WatchConflict("stale_result_fingerprint")
            existing=db.execute("SELECT source_id FROM discovered_sources WHERE watch_id=? AND onion_reference=?",(watch_id,row["onion_reference"])).fetchone()
            source_id=existing[0] if existing else "dws-"+hashlib.sha256((watch_id+row["onion_reference"]).encode()).hexdigest()[:24]
            db.execute("INSERT INTO discovered_sources(source_id,watch_id,onion_reference,protected_url,enabled,created_at,updated_at,archived_at) VALUES(?,?,?,?,1,?,?,NULL) ON CONFLICT(watch_id,onion_reference) DO UPDATE SET enabled=1,updated_at=excluded.updated_at,archived_at=NULL",
                       (source_id,watch_id,row["onion_reference"],row["protected_url"],now,now))
        return self.discovered_source(source_id)

    def discovered_source(self, source_id: str) -> dict[str, Any]:
        with self._connect() as db: row=db.execute("SELECT source_id,watch_id,onion_reference,enabled,created_at,updated_at FROM discovered_sources WHERE source_id=? AND archived_at IS NULL",(source_id,)).fetchone()
        if row is None: raise WatchNotFound()
        return dict(row)|{"enabled":bool(row["enabled"])}

    def list_discovered(self, watch_id: str) -> list[dict[str, Any]]:
        self.get(watch_id)
        with self._connect() as db: rows=db.execute("SELECT source_id,watch_id,onion_reference,enabled,created_at,updated_at FROM discovered_sources WHERE watch_id=? AND archived_at IS NULL ORDER BY created_at DESC LIMIT 100",(watch_id,)).fetchall()
        return [dict(row)|{"enabled":bool(row["enabled"])} for row in rows]

    def list_all_discovered(self) -> list[dict[str,Any]]:
        with self._connect() as db:rows=db.execute("SELECT source_id,watch_id,onion_reference,enabled,created_at,updated_at FROM discovered_sources WHERE archived_at IS NULL ORDER BY created_at DESC LIMIT 100").fetchall()
        return [dict(row)|{"enabled":bool(row["enabled"])} for row in rows]

    def resolve_discovered(self,source_id:str)->dict[str,Any]|None:
        with self._connect() as db:row=db.execute("SELECT source_id,onion_reference,protected_url,enabled FROM discovered_sources WHERE source_id=? AND archived_at IS NULL",(source_id,)).fetchone()
        return (dict(row)|{"enabled":bool(row["enabled"])}) if row else None

    def tracked_urls(self, watch_id: str) -> list[str]:
        with self._connect() as db: rows=db.execute("SELECT protected_url FROM discovered_sources WHERE watch_id=? AND enabled=1 LIMIT 100",(watch_id,)).fetchall()
        return [row[0] for row in rows]

    def set_discovered_enabled(self, source_id: str, enabled: bool) -> dict[str, Any]:
        with self._connect() as db: changed=db.execute("UPDATE discovered_sources SET enabled=?,updated_at=? WHERE source_id=? AND archived_at IS NULL",(int(enabled),utc_now(),source_id)).rowcount
        if not changed: raise WatchNotFound()
        return self.discovered_source(source_id)

    def archive_discovered(self,source_id:str)->None:
        now=utc_now()
        with self._connect() as db:changed=db.execute("UPDATE discovered_sources SET enabled=0,archived_at=?,updated_at=? WHERE source_id=? AND archived_at IS NULL",(now,now,source_id)).rowcount
        if not changed:raise WatchNotFound()

    def commit_scan(self, watch_id: str, candidates: list[dict[str, Any]], *, partial: bool) -> dict[str, int]:
        now=utc_now(); new=changed=0
        with self._connect() as db:
            watch=db.execute("SELECT checkpoint_hash FROM watches WHERE watch_id=? AND enabled=1",(watch_id,)).fetchone()
            if watch is None: raise WatchNotFound()
            for item in candidates:
                old=db.execute("SELECT result_id,content_sha256 FROM results WHERE watch_id=? AND canonical_hash=?",(watch_id,item["canonical_hash"])).fetchone()
                alert_type=None
                if old:
                    if old["content_sha256"] != item["content_sha256"]:
                        changed+=1; alert_type="content_changed"
                        db.execute("UPDATE results SET content_sha256=?,title=?,excerpt=?,last_seen_at=?,matched_keywords=?,collected_at=? WHERE result_id=?",
                                   (item["content_sha256"],item["title"],item["excerpt"],now,json.dumps(item.get("matched_keywords",[]),ensure_ascii=False),item.get("collected_at",now),old["result_id"]))
                    else: db.execute("UPDATE results SET last_seen_at=? WHERE result_id=?",(now,old["result_id"]))
                else:
                    new+=1; alert_type="new_match"; db.execute("INSERT INTO results(result_id,watch_id,canonical_hash,content_sha256,onion_reference,title,excerpt,provider,first_seen_at,last_seen_at,classification_label,classification_confidence,privacy_status,review_reasons,matched_keywords,collected_at,protected_url) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(item["result_id"],watch_id,item["canonical_hash"],item["content_sha256"],item["onion_reference"],item["title"],item["excerpt"],item["provider"],now,now,item.get("classification_label"),item.get("classification_confidence"),item["privacy_status"],",".join(item["review_reasons"]),json.dumps(item.get("matched_keywords",[]),ensure_ascii=False),item.get("collected_at",now),item.get("protected_url")))
                if alert_type:
                    result_id=old["result_id"] if old else item["result_id"]
                    alert_id="dwa-"+hashlib.sha256(f'{watch_id}:{result_id}:{item["content_sha256"]}'.encode()).hexdigest()[:32]
                    db.execute("INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?,?,NULL)",(alert_id,watch_id,result_id,item["onion_reference"],item["content_sha256"],alert_type,json.dumps(item.get("matched_keywords",[]),ensure_ascii=False),now))
            db.execute("DELETE FROM results WHERE watch_id=? AND result_id NOT IN (SELECT result_id FROM results WHERE watch_id=? ORDER BY last_seen_at DESC LIMIT ?)",(watch_id,watch_id,self.max_results))
            total=db.execute("SELECT COUNT(*) FROM results WHERE watch_id=?",(watch_id,)).fetchone()[0]
            checkpoint=hashlib.sha256("\n".join(sorted(x["canonical_hash"] for x in candidates)).encode()).hexdigest()
            db.execute("UPDATE watches SET last_scan_at=?,last_success_at=?,result_count=?,new_result_count=?,checkpoint_hash=?,updated_at=? WHERE watch_id=?",(now,now,total,new,checkpoint,now,watch_id))
        return {"result_count":total,"new_result_count":new,"changed_result_count":changed,"partial":int(partial)}

    def configure_schedule(self, watch_id: str, enabled: bool, interval_seconds: int) -> dict[str, Any]:
        if interval_seconds not in self.ALLOWED_INTERVALS: raise WatchValidationError("schedule_interval")
        now=datetime.now(timezone.utc); next_run=(now+timedelta(seconds=interval_seconds)).isoformat().replace("+00:00","Z") if enabled else None
        with self._connect() as db:
            changed=db.execute("UPDATE watches SET schedule_enabled=?,scan_interval_seconds=?,next_run_at=?,updated_at=? WHERE watch_id=?",
                (int(enabled),interval_seconds,next_run,utc_now(),watch_id)).rowcount
        if not changed: raise WatchNotFound()
        return self.get(watch_id)

    def acquire_leader(self, owner: str, *, lease_seconds: int=30, now: datetime | None=None) -> bool:
        current=now or datetime.now(timezone.utc); expires=(current+timedelta(seconds=lease_seconds)).isoformat().replace("+00:00","Z"); stamp=current.isoformat().replace("+00:00","Z")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT lease_owner,lease_expires_at FROM scheduler_state WHERE singleton=1").fetchone()
            if row["lease_owner"] not in {None,owner} and row["lease_expires_at"] and row["lease_expires_at"]>stamp: return False
            db.execute("UPDATE scheduler_state SET lease_owner=?,lease_expires_at=? WHERE singleton=1",(owner,expires)); return True

    def renew_leader(self, owner: str, *, lease_seconds: int=30, now: datetime | None=None) -> bool:
        current=now or datetime.now(timezone.utc); stamp=current.isoformat().replace("+00:00","Z")
        expires=(current+timedelta(seconds=lease_seconds)).isoformat().replace("+00:00","Z")
        with self._connect() as db:
            changed=db.execute("UPDATE scheduler_state SET lease_expires_at=? WHERE singleton=1 AND lease_owner=? AND lease_expires_at>?",
                               (expires,owner,stamp)).rowcount
        return bool(changed)

    def claim_due(self, owner: str, *, now: datetime | None=None) -> list[dict[str, str]]:
        current=now or datetime.now(timezone.utc); stamp=current.isoformat().replace("+00:00","Z"); claimed=[]
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            leader=db.execute("SELECT lease_owner,lease_expires_at FROM scheduler_state WHERE singleton=1").fetchone()
            if leader["lease_owner"]!=owner or not leader["lease_expires_at"] or leader["lease_expires_at"]<=stamp: return []
            rows=db.execute("SELECT watch_id,next_run_at,scan_interval_seconds FROM watches WHERE enabled=1 AND schedule_enabled=1 AND next_run_at<=? ORDER BY next_run_at LIMIT ?",(stamp,self.max_watches)).fetchall()
            for row in rows:
                occurrence="dwo-"+hashlib.sha256(f'{row["watch_id"]}:{row["next_run_at"]}'.encode()).hexdigest()[:32]
                inserted=db.execute("INSERT OR IGNORE INTO schedule_occurrences VALUES(?,?,?,?,?,NULL)",(occurrence,row["watch_id"],row["next_run_at"],stamp,"claimed")).rowcount
                next_run=(current+timedelta(seconds=row["scan_interval_seconds"])).isoformat().replace("+00:00","Z")
                db.execute("UPDATE watches SET next_run_at=?,last_scheduled_run_at=?,last_attempt_at=?,scheduler_occurrence_id=? WHERE watch_id=?",(next_run,stamp,stamp,occurrence,row["watch_id"]))
                if inserted: claimed.append({"occurrence_id":occurrence,"watch_id":row["watch_id"]})
        return claimed

    def recover_claimed(self, owner: str, *, now: datetime | None=None, stale_seconds: int=300) -> list[dict[str,str]]:
        current=now or datetime.now(timezone.utc); cutoff=(current-timedelta(seconds=stale_seconds)).isoformat().replace("+00:00","Z")
        stamp=current.isoformat().replace("+00:00","Z")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            leader=db.execute("SELECT lease_owner,lease_expires_at FROM scheduler_state WHERE singleton=1").fetchone()
            if leader["lease_owner"]!=owner or not leader["lease_expires_at"] or leader["lease_expires_at"]<=stamp: return []
            rows=db.execute("SELECT occurrence_id,watch_id FROM schedule_occurrences WHERE status IN ('claimed','submitted') AND claimed_at<=? ORDER BY claimed_at LIMIT ?",(cutoff,self.max_watches)).fetchall()
            db.executemany("UPDATE schedule_occurrences SET status='claimed',job_id=NULL,claimed_at=? WHERE occurrence_id=?",((stamp,row["occurrence_id"]) for row in rows))
        return [dict(row) for row in rows]

    def mark_occurrence_submitted(self, occurrence_id: str, job_id: str) -> None:
        with self._connect() as db:
            changed=db.execute("UPDATE schedule_occurrences SET status='submitted',job_id=? WHERE occurrence_id=? AND status='claimed'",(job_id,occurrence_id)).rowcount
        if not changed: raise WatchConflict("occurrence_state")

    def finish_occurrence(self, occurrence_id: str, *, succeeded: bool, failure_category: str | None=None) -> None:
        safe_category=failure_category if failure_category and re.fullmatch(r"[a-z][a-z0-9_]{0,63}",failure_category) else None
        now=utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT watch_id FROM schedule_occurrences WHERE occurrence_id=? AND status IN ('claimed','submitted')",(occurrence_id,)).fetchone()
            if row is None: return
            db.execute("UPDATE schedule_occurrences SET status=? WHERE occurrence_id=?",("completed" if succeeded else "failed",occurrence_id))
            if succeeded:
                db.execute("UPDATE watches SET last_success_at=?,schedule_failure_category=NULL,updated_at=? WHERE watch_id=?",(now,now,row["watch_id"]))
            else:
                db.execute("UPDATE watches SET schedule_failure_category=?,updated_at=? WHERE watch_id=?",(safe_category or "internal_failure",now,row["watch_id"]))

    def alerts(self, *, watch_id: str | None=None, limit: int=25, offset: int=0) -> dict[str, Any]:
        where=" WHERE watch_id=?" if watch_id else ""; args=([watch_id] if watch_id else [])
        with self._connect() as db:
            total=db.execute("SELECT COUNT(*) FROM alerts"+where,args).fetchone()[0]
            unread=db.execute("SELECT COUNT(*) FROM alerts"+where+(" AND" if where else " WHERE")+" read_at IS NULL",args).fetchone()[0]
            rows=db.execute("SELECT * FROM alerts"+where+" ORDER BY created_at DESC,alert_id DESC LIMIT ? OFFSET ?",(*args,limit,offset)).fetchall()
        return {"items":[dict(row) for row in rows],"total":total,"unread":unread,"limit":limit,"offset":offset}

    def mark_alert_read(self, alert_id: str) -> dict[str, Any]:
        with self._connect() as db:
            changed=db.execute("UPDATE alerts SET read_at=COALESCE(read_at,?) WHERE alert_id=?",(utc_now(),alert_id)).rowcount
            row=db.execute("SELECT * FROM alerts WHERE alert_id=?",(alert_id,)).fetchone()
        if not changed or row is None: raise WatchNotFound()
        return dict(row)

    @staticmethod
    def _watch(r):
        value={k:r[k] for k in r.keys() if k not in {"keyword_folded","keywords_json","scheduler_occurrence_id"}}|{"enabled":bool(r["enabled"]),"schedule_enabled":bool(r["schedule_enabled"])}
        value["keywords"]=json.loads(r["keywords_json"]) if r["keywords_json"] else [r["keyword"]]
        return value


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
    def __init__(self, store: SQLiteDarkWebWatchStore, scanner: DarkWebWatchScanner, discovery_scanner=None): self.store,self.scanner,self.discovery_scanner,self._active,self._lock=store,scanner,discovery_scanner,set(),threading.Lock()
    def create_discovery_watch(self, keywords: list[str], match_mode: str, provider_id: str, scan_interval_seconds: int) -> dict[str, Any]:
        from backend.app.pipeline.ingestion.external.application.dark_web_discovery import ProviderMissing
        if self.discovery_scanner is None: raise ProviderMissing()
        self.discovery_scanner.require_provider(provider_id)
        return self.store.create_advanced(keywords,match_mode,provider_id,scan_interval_seconds)
    def scan(self, watch_id: str) -> dict[str, Any]:
        with self._lock:
            if watch_id in self._active: raise WatchConflict("scan_active")
            self._active.add(watch_id)
        try:
            watch=self.store.get(watch_id)
            if not watch["enabled"]: raise WatchConflict("watch_disabled")
            if watch.get("provider_id"):
                from backend.app.pipeline.ingestion.external.application.dark_web_discovery import ProviderMissing
                if self.discovery_scanner is None: raise ProviderMissing()
                matches,partial,scan_counts=self.discovery_scanner.scan(watch,self.store.tracked_urls(watch_id))
            else:
                matches,partial=self.scanner.scan(watch["keyword"]); scan_counts={}
            counts=self.store.commit_scan(watch_id,matches,partial=partial)
            if scan_counts:
                scan_counts["new"]=counts["new_result_count"]
                scan_counts["unchanged"]=max(0,scan_counts.get("matched",0)-counts["new_result_count"])
            return {"status":"partial" if partial else "completed","accepted_records":counts["result_count"],
                    "review_records":0,"rejected_records":0,"skipped_records":counts["result_count"]-counts["new_result_count"],"error_count":int(partial),**scan_counts}
        finally:
            with self._lock: self._active.discard(watch_id)


class DurableDarkWebScheduler:
    """Single-leader, restart-safe scheduler backed by SQLite occurrences."""
    def __init__(self, service: DarkWebWatchService, runner, *, poll_seconds: float=5.0,
                 lease_seconds: int=30, recovery_seconds: int=300, owner: str | None=None) -> None:
        self.service,self.runner=service,runner
        self.poll_seconds=max(0.05,min(float(poll_seconds),30.0)); self.lease_seconds=max(5,min(lease_seconds,300))
        self.recovery_seconds=max(self.lease_seconds,min(recovery_seconds,3600)); self.owner=owner or "scheduler-"+secrets.token_hex(12)
        self._stop=threading.Event(); self._thread: threading.Thread | None=None; self._started=False

    def start(self) -> None:
        if self._thread and self._thread.is_alive(): return
        self._stop.clear(); self._thread=threading.Thread(target=self._run,name="external-dark-web-scheduler",daemon=True)
        self._thread.start()

    def stop(self, *, timeout: float=10.0) -> None:
        self._stop.set()
        if self._thread: self._thread.join(max(0.1,min(timeout,30.0)))

    def tick(self, *, now: datetime | None=None) -> int:
        store=self.service.store
        if not store.renew_leader(self.owner,lease_seconds=self.lease_seconds,now=now):
            if not store.acquire_leader(self.owner,lease_seconds=self.lease_seconds,now=now): return 0
        occurrences=store.recover_claimed(self.owner,now=now,stale_seconds=self.recovery_seconds)
        occurrences.extend(store.claim_due(self.owner,now=now))
        for occurrence in occurrences: self._submit(occurrence)
        return len(occurrences)

    def _submit(self, occurrence: dict[str,str]) -> None:
        occurrence_id,watch_id=occurrence["occurrence_id"],occurrence["watch_id"]
        def operation():
            try:
                result=self.service.scan(watch_id)
                succeeded=result.get("status") in {"completed","partial"}
                self.service.store.finish_occurrence(occurrence_id,succeeded=succeeded,
                    failure_category=None if succeeded else "source_access_unavailable")
                return result
            except Exception:
                self.service.store.finish_occurrence(occurrence_id,succeeded=False,failure_category="internal_failure")
                raise
        try:
            job=self.runner.submit("cmd-"+secrets.token_hex(12),operation,safe_context={"source_id":watch_id})
            self.service.store.mark_occurrence_submitted(occurrence_id,job.job_id)
        except Exception:
            self.service.store.finish_occurrence(occurrence_id,succeeded=False,failure_category="internal_failure")

    def _run(self) -> None:
        while not self._stop.is_set():
            try: self.tick()
            except Exception: pass
            self._stop.wait(self.poll_seconds)

def _safe_text(value: str, maximum: int) -> str:
    value=re.sub(r"https?://\S+|\b\S*\.onion\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:token|password|secret|authorization|cookie|api[_-]?key)\s*[=:]\s*\S+","[redacted]",value,flags=re.I)
    return " ".join(value.split())[:maximum]
