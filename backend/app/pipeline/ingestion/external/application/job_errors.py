from __future__ import annotations


class SafeJobFailure(RuntimeError):
    """A deliberately public, bounded asynchronous-job failure."""

    def __init__(self, code: str, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message
        self.retryable = retryable
