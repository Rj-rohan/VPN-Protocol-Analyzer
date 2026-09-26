"""Analysis execution outside the HTTP request.

`AnalysisQueue` is the boundary a distributed worker (Celery, RQ, Arq) would
replace; this implementation uses an in-process thread pool.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.exceptions import AnalyzerError
from app.core.models import Analysis, AnalysisStatus
from app.db.repositories import complete_analysis, fail_analysis, mark_running

logger = logging.getLogger(__name__)


def run_analysis(analysis_id: UUID, session_factory: Callable[[], Session]) -> None:
    from app.pipeline import run_pipeline

    with session_factory() as db:
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            return
        mark_running(analysis)
        db.commit()
        try:
            result = run_pipeline(Path(analysis.capture.stored_path))
            complete_analysis(db, analysis, result)
        except AnalyzerError as exc:
            fail_analysis(analysis, str(exc))
        except Exception:  # never leak internals into stored results; details go to the server log
            logger.exception("Analysis %s crashed", analysis_id)
            fail_analysis(analysis, "Internal analysis error; see server logs.")
        db.commit()


class AnalysisQueue:
    def __init__(self, session_factory: Callable[[], Session], mode: str = "background", workers: int = 2):
        self.session_factory = session_factory
        self.mode = mode
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="analysis") if mode == "background" else None

    def enqueue(self, analysis_id: UUID) -> None:
        if self._executor is None:
            run_analysis(analysis_id, self.session_factory)
        else:
            self._executor.submit(run_analysis, analysis_id, self.session_factory)

    def resume_pending(self) -> int:
        """Re-submit analyses interrupted by a restart."""
        with self.session_factory() as db:
            pending = db.scalars(select(Analysis.id).where(Analysis.status.in_([AnalysisStatus.queued, AnalysisStatus.running]))).all()
        for analysis_id in pending:
            self.enqueue(analysis_id)
        return len(pending)

    def shutdown(self) -> None:
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)


_queue: AnalysisQueue | None = None


def get_queue() -> AnalysisQueue:
    global _queue
    if _queue is None:
        from app.db.database import SessionLocal

        _queue = AnalysisQueue(SessionLocal, settings.analysis_execution, settings.analysis_workers)
    return _queue


def set_queue(queue: AnalysisQueue | None) -> None:
    global _queue
    _queue = queue
