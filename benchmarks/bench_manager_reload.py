"""Stress atomic catalog reloads under concurrent deterministic traffic."""

import argparse
from collections import defaultdict, deque
import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import string
import sys
from threading import Condition, Event, Lock, Thread, current_thread, enumerate as threads
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.synthetic_data import build_dataset
from llm_ffw import (
    FirewallManagerState,
    FirewallReloadError,
    FirewallManager,
    ProcessScannerPoolConfig,
    RuleScannerConfig,
    SecretCatalog,
    SecretSignature,
)


_REDACTION = "[REDACTED]"
_CUSTOM_VALUE = "acme_live_" + "A" * 12


@dataclass(frozen=True, slots=True)
class ManagerReloadResult:
    traffic_requests: int
    reload_probe_requests: int
    builtin_generation_requests: int
    extended_generation_requests: int
    reloads: int
    max_reload_seconds: float
    mean_reload_seconds: float
    requests_per_second: float
    peak_tree_rss_mib: float
    peak_processes: int
    rollback_preserved: bool
    shutdown_during_reload: bool


def _extension(version: str) -> SecretCatalog:
    return SecretCatalog(
        catalog_id="benchmark.manager.extended",
        version=version,
        signatures=(
            SecretSignature(
                signature_id="benchmark.acme.service_token",
                provider="benchmark_acme",
                secret_type="service_token",
                prefixes=("acme_live_",),
                suffix_chars=string.ascii_letters + string.digits,
                min_suffix_chars=12,
                max_suffix_chars=12,
                boundary_chars=string.ascii_letters + string.digits + "_",
                source="internal://benchmark/acme-service-token",
            ),
        ),
    )


def _invalid_extension() -> SecretCatalog:
    return SecretCatalog(
        catalog_id="benchmark.manager.invalid",
        version="1",
        signatures=(
            SecretSignature(
                signature_id="benchmark.invalid.nested",
                provider="benchmark_acme",
                secret_type="service_token",
                prefixes=("sk-benchmark-",),
                suffix_chars=string.ascii_letters + string.digits,
                min_suffix_chars=12,
                max_suffix_chars=12,
                boundary_chars=string.ascii_letters + string.digits + "_-",
                source="internal://benchmark/invalid-nested-token",
            ),
        ),
    )


def _build_gate_text(size: int) -> tuple[str, int]:
    dataset = build_dataset(size)
    suffix = " " + _CUSTOM_VALUE
    start = size - len(suffix)
    if start <= 0 or any(item.end > start for item in dataset.expected_findings):
        raise ValueError("size is too small for the manager reload corpus")
    text = dataset.text[:start] + suffix
    if text.count(_CUSTOM_VALUE) != 1:
        raise RuntimeError("manager corpus custom marker is not unique")
    return text, len(dataset.expected_findings)


def _classify_result(processed: str, expected_builtin: int) -> str:
    redactions = processed.count(_REDACTION)
    if _CUSTOM_VALUE in processed and redactions == expected_builtin:
        return "builtin"
    if _CUSTOM_VALUE not in processed and redactions == expected_builtin + 1:
        return "extended"
    raise RuntimeError("request result did not match exactly one catalog generation")


def _windows_process_table() -> dict[int, int]:
    from ctypes import wintypes

    class ProcessEntry32(ctypes.Structure):
        _fields_ = (
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ProcessEntry32),
    )
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ProcessEntry32),
    )
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    table: dict[int, int] = {}
    try:
        entry = ProcessEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        available = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while available:
            table[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            available = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return table


def _linux_process_table() -> dict[int, int]:
    table: dict[int, int] = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            value = (path / "stat").read_text(encoding="ascii")
            remainder = value[value.rfind(")") + 2 :].split()
            table[int(path.name)] = int(remainder[1])
        except (
            FileNotFoundError,
            IndexError,
            PermissionError,
            ProcessLookupError,
            ValueError,
        ):
            continue
    return table


def _descendant_pids(root_pid: int) -> set[int]:
    if sys.platform == "win32":
        table = _windows_process_table()
    elif sys.platform.startswith("linux"):
        table = _linux_process_table()
    else:
        raise RuntimeError("manager memory gate supports Windows and Linux")
    children: dict[int, list[int]] = defaultdict(list)
    for pid, parent in table.items():
        children[parent].append(pid)
    descendants: set[int] = set()
    pending = deque((root_pid,))
    while pending:
        parent = pending.popleft()
        for child in children.get(parent, ()):
            if child not in descendants:
                descendants.add(child)
                pending.append(child)
    return descendants


def _windows_rss_bytes(pid: int) -> int:
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = (
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCounters),
        wintypes.DWORD,
    )
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    process = kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
    if not process:
        return 0
    try:
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(
            process,
            ctypes.byref(counters),
            counters.cb,
        ):
            return 0
        return int(counters.WorkingSetSize)
    finally:
        kernel32.CloseHandle(process)


def _linux_rss_bytes(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        pass
    return 0


def _tree_memory(root_pid: int) -> tuple[int, int]:
    pids = _descendant_pids(root_pid) | {root_pid}
    rss = sum(
        _windows_rss_bytes(pid)
        if sys.platform == "win32"
        else _linux_rss_bytes(pid)
        for pid in pids
    )
    return rss, len(pids)


def _persistent_runtime_helpers() -> set[int]:
    """Return interpreter-owned helpers that intentionally outlive a pool."""

    if not sys.platform.startswith("linux"):
        return set()
    helpers: set[int] = set()
    for pid in _descendant_pids(os.getpid()):
        try:
            command = Path(f"/proc/{pid}/cmdline").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if b"multiprocessing.resource_tracker" in command:
            helpers.add(pid)
    return helpers


class _MemorySampler:
    def __init__(self, interval_seconds: float) -> None:
        self._interval_seconds = interval_seconds
        self._stop = Event()
        self._lock = Lock()
        self._peak_rss = 0
        self._peak_processes = 0
        self._error: BaseException | None = None
        self._thread = Thread(
            target=self._run,
            name="manager-memory-sampler",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> tuple[int, int]:
        self._stop.set()
        self._thread.join(10)
        if self._thread.is_alive():
            raise RuntimeError("memory sampler did not stop")
        if self._error is not None:
            raise RuntimeError(
                f"memory sampler failed: {type(self._error).__name__}"
            )
        with self._lock:
            return self._peak_rss, self._peak_processes

    def _run(self) -> None:
        try:
            while True:
                rss, process_count = _tree_memory(os.getpid())
                with self._lock:
                    self._peak_rss = max(self._peak_rss, rss)
                    self._peak_processes = max(
                        self._peak_processes,
                        process_count,
                    )
                if self._stop.wait(self._interval_seconds):
                    return
        except BaseException as exc:
            self._error = exc


def _pool_config(
    workers: int,
    concurrency: int,
    max_tasks_per_child: int,
) -> ProcessScannerPoolConfig:
    return ProcessScannerPoolConfig(
        max_workers=workers,
        max_in_flight=max(workers, concurrency),
        max_tasks_per_child=max_tasks_per_child,
        admission_timeout_seconds=5.0,
    )


def _run_shutdown_probe(
    text: str,
    expected_builtin: int,
    *,
    workers: int,
    concurrency: int,
    max_tasks_per_child: int,
    timeout: float,
) -> None:
    manager = FirewallManager(
        scanner_config=RuleScannerConfig(max_input_chars=len(text)),
        pool_config=_pool_config(workers, concurrency, max_tasks_per_child),
        request_timeout_seconds=timeout,
    ).start()
    outputs: list[str] = []
    failures: list[str] = []

    def request() -> None:
        try:
            outputs.append(manager.sanitize_input(text))
        except BaseException as exc:
            failures.append(type(exc).__name__)

    callers = [Thread(target=request, name=f"shutdown-probe-{index}") for index in range(concurrency)]
    for caller in callers:
        caller.start()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with manager._condition:
            if manager._active.in_flight >= concurrency:
                break
        time.sleep(0.001)
    else:
        manager.close()
        raise TimeoutError("shutdown probe did not acquire old-generation leases")

    reload_failure: list[str] = []

    def reload_generation() -> None:
        try:
            manager.reload(
                additional_secret_catalog=_extension("3.0.0+shutdown.1")
            )
        except BaseException as exc:
            reload_failure.append(type(exc).__name__)

    reloader = Thread(target=reload_generation, name="shutdown-probe-reload")
    reloader.start()
    deadline = time.monotonic() + timeout
    while reloader.is_alive() and time.monotonic() < deadline:
        if manager.capabilities().secret_catalog.signature_count == 29:
            break
        time.sleep(0.001)
    if not reloader.is_alive():
        manager.close()
        raise RuntimeError("shutdown probe reload drained before close began")

    close_failure: list[str] = []

    def close_manager() -> None:
        try:
            manager.close()
        except BaseException as exc:
            close_failure.append(type(exc).__name__)

    closer = Thread(target=close_manager, name="shutdown-probe-close")
    closer.start()
    for caller in callers:
        caller.join(timeout)
    reloader.join(timeout)
    closer.join(timeout)
    if any(thread.is_alive() for thread in (*callers, reloader, closer)):
        raise TimeoutError("shutdown probe thread did not finish")
    if failures or reload_failure or close_failure:
        raise RuntimeError("shutdown probe operation failed")
    if manager.state is not FirewallManagerState.CLOSED:
        raise RuntimeError("manager did not close during active reload")
    if len(outputs) != concurrency:
        raise RuntimeError("shutdown probe lost a request")
    if any(
        _classify_result(output, expected_builtin) != "builtin"
        for output in outputs
    ):
        raise RuntimeError("shutdown probe request changed generation")


def run_manager_reload_gate(
    *,
    size: int,
    workers: int,
    concurrency: int,
    reloads: int,
    min_requests: int,
    max_tasks_per_child: int,
    timeout: float,
    sample_interval_seconds: float,
) -> ManagerReloadResult:
    if min(size, workers, concurrency, reloads, min_requests, max_tasks_per_child) <= 0:
        raise ValueError("gate counts and size must be positive")
    if concurrency < workers:
        raise ValueError("concurrency must be at least workers")
    if timeout <= 0 or sample_interval_seconds <= 0:
        raise ValueError("timeout and sample interval must be positive")

    text, expected_builtin = _build_gate_text(size)
    baseline_children = _descendant_pids(os.getpid())
    baseline_threads = {
        thread.ident for thread in threads() if thread.ident is not None
    }
    sampler = _MemorySampler(sample_interval_seconds)
    sampler.start()
    manager = FirewallManager(
        scanner_config=RuleScannerConfig(max_input_chars=size),
        pool_config=_pool_config(workers, concurrency, max_tasks_per_child),
        request_timeout_seconds=timeout,
    )
    stop = Event()
    statistics = Condition(Lock())
    submitted = 0
    completed_ids: set[int] = set()
    generation_counts = {"builtin": 0, "extended": 0}
    request_failures: list[str] = []

    def caller() -> None:
        nonlocal submitted
        while not stop.is_set():
            with statistics:
                request_id = submitted
                submitted += 1
                statistics.notify_all()
            try:
                generation = _classify_result(
                    manager.sanitize_input(text),
                    expected_builtin,
                )
            except BaseException as exc:
                with statistics:
                    request_failures.append(type(exc).__name__)
                    statistics.notify_all()
                stop.set()
                return
            with statistics:
                if request_id in completed_ids:
                    request_failures.append("DuplicateRequestCompletion")
                    stop.set()
                    return
                completed_ids.add(request_id)
                generation_counts[generation] += 1
                statistics.notify_all()

    reload_durations: list[float] = []
    rollback_preserved = False
    callers: list[Thread] = []
    started = time.perf_counter()
    try:
        manager.start()
        callers = [
            Thread(target=caller, name=f"manager-load-{index}")
            for index in range(concurrency)
        ]
        for thread in callers:
            thread.start()
        with statistics:
            deadline = time.monotonic() + timeout
            while len(completed_ids) < concurrency and not request_failures:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("initial manager traffic did not complete")
                statistics.wait(remaining)

        before = manager.capabilities()
        try:
            manager.reload(additional_secret_catalog=_invalid_extension())
        except FirewallReloadError as exc:
            rollback_preserved = (
                not exc.activated
                and exc.cause_type == "ValueError"
                and manager.capabilities() == before
            )
        if not rollback_preserved:
            raise RuntimeError("failed candidate changed the active generation")

        for index in range(reloads):
            reload_started = time.perf_counter()
            if index % 2:
                manager.reload_builtin_catalog()
            else:
                manager.reload(
                    additional_secret_catalog=_extension(
                        f"3.0.0+stress.{index + 1}"
                    )
                )
            reload_durations.append(time.perf_counter() - reload_started)
            generation = _classify_result(
                manager.sanitize_input(text),
                expected_builtin,
            )
            with statistics:
                generation_counts[generation] += 1

        with statistics:
            deadline = time.monotonic() + timeout
            while len(completed_ids) < min_requests and not request_failures:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("minimum manager traffic did not complete")
                statistics.wait(remaining)
    finally:
        stop.set()
        for thread in callers:
            thread.join(timeout)
        try:
            manager.close()
        finally:
            if sys.exception() is not None:
                sampler.stop()

    try:
        elapsed = time.perf_counter() - started
        if any(thread.is_alive() for thread in callers):
            raise TimeoutError("manager traffic thread did not stop")
        if request_failures:
            raise RuntimeError(f"manager traffic failed: {request_failures[0]}")
        if len(completed_ids) != submitted:
            raise RuntimeError("manager gate lost a submitted request")
        if (
            generation_counts["builtin"] == 0
            or generation_counts["extended"] == 0
        ):
            raise RuntimeError(
                "manager gate did not observe both catalog generations"
            )

        _run_shutdown_probe(
            text,
            expected_builtin,
            workers=workers,
            concurrency=concurrency,
            max_tasks_per_child=max_tasks_per_child,
            timeout=timeout,
        )
        deadline = time.monotonic() + 10
        while (
            _descendant_pids(os.getpid())
            - baseline_children
            - _persistent_runtime_helpers()
        ):
            if time.monotonic() >= deadline:
                raise RuntimeError("manager gate leaked a scanner worker process")
            time.sleep(0.01)
    finally:
        peak_rss, peak_processes = sampler.stop()
    remaining_threads = {
        thread.ident
        for thread in threads()
        if thread.ident is not None and thread is not current_thread()
    } - baseline_threads
    if remaining_threads:
        raise RuntimeError("manager gate leaked a thread")

    return ManagerReloadResult(
        traffic_requests=len(completed_ids),
        reload_probe_requests=reloads,
        builtin_generation_requests=generation_counts["builtin"],
        extended_generation_requests=generation_counts["extended"],
        reloads=reloads,
        max_reload_seconds=max(reload_durations),
        mean_reload_seconds=sum(reload_durations) / len(reload_durations),
        requests_per_second=len(completed_ids) / elapsed,
        peak_tree_rss_mib=peak_rss / (1024 * 1024),
        peak_processes=peak_processes,
        rollback_preserved=rollback_preserved,
        shutdown_during_reload=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--reloads", type=int, default=4)
    parser.add_argument("--min-requests", type=int, default=16)
    parser.add_argument("--max-tasks-per-child", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--memory-sample-ms", type=float, default=10.0)
    parser.add_argument("--max-peak-tree-rss-mib", type=float)
    parser.add_argument("--max-reload-seconds", type=float)
    parser.add_argument("--min-requests-per-second", type=float)
    args = parser.parse_args()
    result = run_manager_reload_gate(
        size=args.size,
        workers=args.workers,
        concurrency=args.concurrency,
        reloads=args.reloads,
        min_requests=args.min_requests,
        max_tasks_per_child=args.max_tasks_per_child,
        timeout=args.timeout,
        sample_interval_seconds=args.memory_sample_ms / 1000,
    )
    print(f"traffic_requests={result.traffic_requests}")
    print(f"reload_probe_requests={result.reload_probe_requests}")
    print(f"builtin_generation_requests={result.builtin_generation_requests}")
    print(f"extended_generation_requests={result.extended_generation_requests}")
    print(f"reloads={result.reloads}")
    print(f"max_reload_seconds={result.max_reload_seconds:.6f}")
    print(f"mean_reload_seconds={result.mean_reload_seconds:.6f}")
    print(f"requests_per_second={result.requests_per_second:.2f}")
    print(f"peak_tree_rss_mib={result.peak_tree_rss_mib:.2f}")
    print(f"peak_processes={result.peak_processes}")
    print(f"rollback_preserved={str(result.rollback_preserved).lower()}")
    print(f"shutdown_during_reload={str(result.shutdown_during_reload).lower()}")
    if (
        args.max_peak_tree_rss_mib is not None
        and result.peak_tree_rss_mib > args.max_peak_tree_rss_mib
    ):
        raise SystemExit("manager reload peak-memory gate failed")
    if (
        args.max_reload_seconds is not None
        and result.max_reload_seconds > args.max_reload_seconds
    ):
        raise SystemExit("manager reload latency gate failed")
    if (
        args.min_requests_per_second is not None
        and result.requests_per_second < args.min_requests_per_second
    ):
        raise SystemExit("manager reload throughput gate failed")


if __name__ == "__main__":
    main()
