from __future__ import annotations

import ctypes
import ctypes.wintypes
import os


if os.name == "nt":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.wintypes.LPVOID, ctypes.wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = ctypes.wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = ctypes.wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.UINT]
    kernel32.TerminateJobObject.restype = ctypes.wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL


class WindowsJob:
    """Win32 Job Object wrapper for supervising one Windows process tree."""

    def __init__(self, name: str | None = None) -> None:
        if os.name != "nt":
            raise OSError("WindowsJob is only available on Windows")
        if name is not None and (not name or "\x00" in name):
            raise ValueError("invalid job name")
        self.handle = kernel32.CreateJobObjectW(None, name)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process_handle: int) -> None:
        if not process_handle:
            raise ValueError("invalid process handle")
        if not kernel32.AssignProcessToJobObject(self.handle, process_handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def terminate(self, exit_code: int = 1) -> None:
        if not kernel32.TerminateJobObject(self.handle, exit_code):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if getattr(self, "handle", None):
            kernel32.CloseHandle(self.handle)
            self.handle = None
