from __future__ import annotations

import sys
import threading

KILLED_EXIT_CODE = 1
PATH_BUFFER = 1024
MAX_PATH_BUFFER = 32_768

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    KILL_ON_JOB_CLOSE = 0x2000
    EXTENDED_LIMIT_INFORMATION = 9
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_TERMINATE = 0x0001
    DRIVE_REMOTE = 4

    class _Counters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_ulonglong)
            for name in ("reads", "writes", "others", "read_bytes", "written_bytes", "other_bytes")
        ]

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_longlong),
            ("job_time", ctypes.c_longlong),
            ("flags", wintypes.DWORD),
            ("minimum_working_set", ctypes.c_size_t),
            ("maximum_working_set", ctypes.c_size_t),
            ("process_limit", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority", wintypes.DWORD),
            ("scheduling", wintypes.DWORD),
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("basic", _BasicLimits),
            ("io", _Counters),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t),
            ("peak_job_memory", ctypes.c_size_t),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.GetLongPathNameW.restype = wintypes.DWORD
    _kernel32.GetLongPathNameW.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    _kernel32.GetDriveTypeW.restype = wintypes.UINT
    _kernel32.GetDriveTypeW.argtypes = (wintypes.LPCWSTR,)

    def remote_drive(drive: str) -> bool:
        try:
            return bool(_kernel32.GetDriveTypeW(drive + "\\") == DRIVE_REMOTE)
        except (OSError, ValueError, TypeError, ctypes.ArgumentError):
            return False

    def _create_job(pid: int) -> int | None:
        job = _kernel32.CreateJobObjectW(None, None)
        if not job:
            return None
        limits = _ExtendedLimits()
        limits.basic.flags = KILL_ON_JOB_CLOSE
        process = None
        try:
            if not _kernel32.SetInformationJobObject(
                job, EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits), ctypes.sizeof(limits)
            ):
                raise OSError(ctypes.get_last_error())
            process = _kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
            if not process or not _kernel32.AssignProcessToJobObject(job, process):
                raise OSError(ctypes.get_last_error())
        except OSError:
            _kernel32.CloseHandle(job)
            return None
        finally:
            if process:
                _kernel32.CloseHandle(process)
        return int(job)

    def _terminate_job(job: int) -> bool:
        return bool(_kernel32.TerminateJobObject(job, KILLED_EXIT_CODE))

    def _close_handle(handle: int) -> None:
        _kernel32.CloseHandle(handle)

    def long_path(path: str) -> str | None:
        size = PATH_BUFFER
        while size <= MAX_PATH_BUFFER:
            buffer = ctypes.create_unicode_buffer(size)
            needed = _kernel32.GetLongPathNameW(path, buffer, size)
            if needed == 0:
                return None
            if needed < size:
                return buffer.value
            size = needed + 1
        return None

else:

    def _create_job(pid: int) -> int | None:
        return None

    def _terminate_job(job: int) -> bool:
        return False

    def _close_handle(handle: int) -> None:
        return None

    def long_path(path: str) -> str | None:
        return None

    def remote_drive(drive: str) -> bool:
        return False


class Job:
    def __init__(self, handle: int | None) -> None:
        self._handle = handle
        self._lock = threading.Lock()

    @classmethod
    def around(cls, pid: int) -> Job:
        return cls(_create_job(pid))

    @property
    def active(self) -> bool:
        with self._lock:
            return self._handle is not None

    def terminate(self) -> bool:
        with self._lock:
            return self._handle is not None and _terminate_job(self._handle)

    def close(self) -> None:
        with self._lock:
            handle, self._handle = self._handle, None
        if handle is not None:
            _close_handle(handle)
