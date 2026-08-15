"""Measure isolated peak memory for one balanced-policy request."""

import argparse
import ctypes
from multiprocessing.connection import Connection
import multiprocessing
from pathlib import Path
import sys
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.synthetic_data import build_dataset
from llm_ffw import Action, Firewall, Scanner, ScannerConfig


def _peak_rss_bytes() -> int:
    if sys.platform == "win32":
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

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        )
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        process = kernel32.GetCurrentProcess()
        if not psapi.GetProcessMemoryInfo(
            process,
            ctypes.byref(counters),
            counters.cb,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(counters.PeakWorkingSetSize)

    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _measure(size: int, connection: Connection) -> None:
    try:
        tracemalloc.start()
        dataset = build_dataset(size)
        firewall = Firewall(scanner=Scanner(config=ScannerConfig(max_input_chars=size)))
        result = firewall.process(dataset.text)
        _, python_peak = tracemalloc.get_traced_memory()
        if result.decision is not Action.REDACT or result.processed_text is None:
            raise RuntimeError("balanced policy did not redact memory-gate request")
        if len(result.findings) != len(dataset.expected_findings):
            raise RuntimeError("memory-gate finding count changed")
        connection.send(
            ("ok", _peak_rss_bytes(), python_peak, len(result.findings))
        )
    except BaseException as exc:
        connection.send(("error", type(exc).__name__))
    finally:
        connection.close()


def measure(size: int, timeout: float) -> tuple[int, int, int]:
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_measure, args=(size, child))
    process.start()
    child.close()
    try:
        if not parent.poll(timeout):
            process.terminate()
            process.join(10)
            if process.is_alive():
                process.kill()
                process.join(10)
            raise TimeoutError("memory gate timed out")
        message = parent.recv()
    finally:
        parent.close()
    process.join(10)
    if process.is_alive():
        process.kill()
        process.join(10)
        raise RuntimeError("memory measurement child did not exit")
    if message[0] != "ok":
        raise RuntimeError(f"memory measurement failed: {message[1]}")
    return message[1], message[2], message[3]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=8_000_000)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--max-peak-rss-mib", type=float)
    args = parser.parse_args()
    if args.size <= 0 or args.timeout <= 0:
        parser.error("--size and --timeout must be positive")
    if args.max_peak_rss_mib is not None and args.max_peak_rss_mib <= 0:
        parser.error("--max-peak-rss-mib must be positive")

    peak_rss, python_peak, findings = measure(args.size, args.timeout)
    peak_rss_mib = peak_rss / (1024 * 1024)
    python_peak_mib = python_peak / (1024 * 1024)
    print(f"peak_rss_mib={peak_rss_mib:.2f}")
    print(f"python_allocations_peak_mib={python_peak_mib:.2f}")
    print(f"findings={findings}")
    if args.max_peak_rss_mib is not None and peak_rss_mib > args.max_peak_rss_mib:
        raise SystemExit(
            "memory gate failed: "
            f"{peak_rss_mib:.2f} MiB > {args.max_peak_rss_mib:.2f} MiB"
        )


if __name__ == "__main__":
    main()
