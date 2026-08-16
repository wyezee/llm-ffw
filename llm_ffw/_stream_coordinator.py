"""Internal coordinator for bounded incremental rule detectors."""

from ._incremental_stream import _IncrementalRedactionEngine
from ._payment_card_stream import _PaymentCardStreamDetector
from .findings import Finding


class _IncrementalStreamCoordinator:
    """Coordinate detector watermarks with one merged redaction engine."""

    __slots__ = (
        "_engine",
        "_max_buffered_chars",
        "_payment_detector",
        "_payment_pending",
        "_source_offset",
        "_source_pending",
    )

    def __init__(
        self,
        *,
        engine: _IncrementalRedactionEngine,
        payment_detector: _PaymentCardStreamDetector | None,
    ) -> None:
        if not isinstance(engine, _IncrementalRedactionEngine):
            raise TypeError("engine must be an incremental redaction engine")
        if payment_detector is not None and not isinstance(
            payment_detector,
            _PaymentCardStreamDetector,
        ):
            raise TypeError("payment_detector has an invalid type")
        self._engine = engine
        self._payment_detector = payment_detector
        self._source_pending = ""
        self._source_offset = 0
        self._payment_pending: list[Finding] = []
        self._max_buffered_chars = 0

    @property
    def findings(self) -> tuple[Finding, ...]:
        return self._engine.findings

    @property
    def buffered_chars(self) -> int:
        detector_chars = (
            self._payment_detector.buffered_chars
            if self._payment_detector is not None
            else 0
        )
        return (
            len(self._source_pending)
            + self._engine.buffered_chars
            + detector_chars
        )

    @property
    def max_buffered_chars(self) -> int:
        return max(self._max_buffered_chars, self.buffered_chars)

    def feed(self, chunk: str) -> str:
        if not isinstance(chunk, str):
            raise TypeError("chunk must be a string")
        if not chunk:
            raise ValueError("chunk must not be empty")
        if self._payment_detector is None:
            output = self._engine.feed(chunk)
            self._record_peak()
            return output

        self._source_pending += chunk
        delta = self._payment_detector.feed(chunk)
        self._payment_pending.extend(delta.findings)
        release_through = delta.safe_through
        overflow_start = self._payment_detector.overflow_start
        if overflow_start is not None:
            release_through = min(release_through, overflow_start)
        release_through = self._hold_crossing_findings(release_through)
        self._record_peak()
        output = self._release(release_through)
        self._record_peak()
        return output

    def finish(self) -> str:
        if self._payment_detector is None:
            return self._engine.finish()
        delta = self._payment_detector.finish()
        self._payment_pending.extend(delta.findings)
        self._record_peak()
        output = self._release(delta.safe_through)
        tail = self._engine.finish()
        self._source_pending = ""
        self._payment_pending.clear()
        return output + tail

    def cancel(self) -> None:
        self._source_pending = ""
        self._payment_pending.clear()
        if self._payment_detector is not None:
            self._payment_detector.cancel()
        self._engine.cancel()

    def _hold_crossing_findings(self, release_through: int) -> int:
        for finding in self._payment_pending:
            if finding.span.start < release_through < finding.span.end:
                release_through = finding.span.start
        return release_through

    def _release(self, release_through: int) -> str:
        if release_through < self._source_offset:
            raise RuntimeError("detector watermark moved backwards")
        local_end = release_through - self._source_offset
        if local_end > len(self._source_pending):
            raise RuntimeError("detector watermark exceeds buffered source")
        if local_end == 0:
            return ""
        selected: list[Finding] = []
        remaining: list[Finding] = []
        for finding in self._payment_pending:
            if finding.span.end <= release_through:
                selected.append(finding)
            else:
                remaining.append(finding)
        source = self._source_pending[:local_end]
        self._source_pending = self._source_pending[local_end:]
        self._source_offset = release_through
        self._payment_pending = remaining
        return self._engine.feed(source, external_findings=tuple(selected))

    def _record_peak(self) -> None:
        self._max_buffered_chars = max(
            self._max_buffered_chars,
            self.buffered_chars,
        )


__all__: list[str] = []
