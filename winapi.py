#!/usr/bin/env python
# coding: utf-8
# wrapping selected windows api functions
import ctypes

sizeof      = ctypes.sizeof
Structure   = ctypes.Structure

windll = ctypes.windll

def RaiseIfZero(result, func = None, arguments = ()):
    if not result:
        raise ctypes.WinError()
    return result

LPVOID      = ctypes.c_void_p
CHAR        = ctypes.c_char
DWORD       = ctypes.c_uint
LONG        = ctypes.c_long
BOOL        = DWORD
TCHAR       = CHAR
HANDLE      = LPVOID

NULL        = None
TRUE        = 1
FALSE       = 0

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

ERROR_NO_MORE_FILES                 = 18


class Handle (object):
    def __init__(self, aHandle = None, bOwnership = True):
        super(Handle, self).__init__()
        self.value      = self._normalize(aHandle)
        self.bOwnership = bOwnership

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __copy__(self):
        return self.dup()

    def __deepcopy__(self):
        return self.dup()

    @property
    def _as_parameter_(self):
        return HANDLE(self.value)

    @staticmethod
    def from_param(value):
        return HANDLE(value)

    def close(self):
        if self.bOwnership and self.value not in (None, INVALID_HANDLE_VALUE):
            try:
                CloseHandle(self.value)
            finally:
                self.value = None

    def dup(self):
        return DuplicateHandle(self.value)

    @staticmethod
    def _normalize(value):
        if value is None:
            value = 0
        elif hasattr(value, 'value'):
            value = value.value
        else:
            value = long(value)
        return value

    def wait(self, dwMilliseconds = None):
        if dwMilliseconds is None:
            dwMilliseconds = INFINITE
        r = WaitForSingleObject(self.value, dwMilliseconds)
        if r != WAIT_OBJECT_0:
            raise ctypes.WinError(r)

class ThreadHandle (Handle):
    def get_tid(self):
        return GetThreadId(self.value)


def GetLastError():
    _GetLastError = windll.kernel32.GetLastError
    _GetLastError.argtypes = []
    _GetLastError.restype  = DWORD
    return _GetLastError()



def CloseHandle(hHandle):
    if isinstance(hHandle, Handle):
        hHandle.close()
    else:
        _CloseHandle = windll.kernel32.CloseHandle
        _CloseHandle.argtypes = [HANDLE]
        _CloseHandle.restype  = bool
        _CloseHandle.errcheck = RaiseIfZero
        _CloseHandle(hHandle)


def OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId):
    _OpenThread = windll.kernel32.OpenThread
    _OpenThread.argtypes = [DWORD, BOOL, DWORD]
    _OpenThread.restype  = HANDLE

    hProcess = _OpenThread(dwDesiredAccess, bool(bInheritHandle), dwThreadId)
    if hProcess == NULL:
        raise ctypes.WinError()
    return ThreadHandle(hProcess)

def SuspendThread(hThread):
    _SuspendThread = windll.kernel32.SuspendThread
    _SuspendThread.argtypes = [HANDLE]
    _SuspendThread.restype  = DWORD

    previousCount = _SuspendThread(hThread)
    if previousCount == DWORD(-1).value:
        raise ctypes.WinError()
    return previousCount

def ResumeThread(hThread):
    _ResumeThread = windll.kernel32.ResumeThread
    _ResumeThread.argtypes = [HANDLE]
    _ResumeThread.restype  = DWORD

    previousCount = _ResumeThread(hThread)
    if previousCount == DWORD(-1).value:
        raise ctypes.WinError()
    return previousCount


THREAD_SUSPEND_RESUME           = 0x0002


TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)

class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          LONG),
        ('tpDeltaPri',         LONG),
        ('dwFlags',            DWORD),
    ]
LPTHREADENTRY32 = ctypes.POINTER(THREADENTRY32)

class PROCESSENTRY32(Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ProcessID',       DWORD),
        ('th32DefaultHeapID',   LPVOID),
        ('th32ModuleID',        DWORD),
        ('cntThreads',          DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase',      LONG),
        ('dwFlags',             DWORD),
        ('szExeFile',           TCHAR * 260),
    ]
LPPROCESSENTRY32 = ctypes.POINTER(PROCESSENTRY32)

def CreateToolhelp32Snapshot(dwFlags = TH32CS_SNAPALL, th32ProcessID = 0):
    _CreateToolhelp32Snapshot = windll.kernel32.CreateToolhelp32Snapshot
    _CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
    _CreateToolhelp32Snapshot.restype  = HANDLE

    hSnapshot = _CreateToolhelp32Snapshot(dwFlags, th32ProcessID)
    if hSnapshot == INVALID_HANDLE_VALUE:
        raise ctypes.WinError()
    return Handle(hSnapshot)

def Process32First(hSnapshot):
    _Process32First = windll.kernel32.Process32First
    _Process32First.argtypes = [HANDLE, LPPROCESSENTRY32]
    _Process32First.restype  = bool

    pe        = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    success = _Process32First(hSnapshot, ctypes.byref(pe))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return pe

def Process32Next(hSnapshot, pe = None):
    _Process32Next = windll.kernel32.Process32Next
    _Process32Next.argtypes = [HANDLE, LPPROCESSENTRY32]
    _Process32Next.restype  = bool

    if pe is None:
        pe = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    success = _Process32Next(hSnapshot, ctypes.byref(pe))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return pe

def Thread32First(hSnapshot):
    _Thread32First = windll.kernel32.Thread32First
    _Thread32First.argtypes = [HANDLE, LPTHREADENTRY32]
    _Thread32First.restype  = bool

    te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = _Thread32First(hSnapshot, ctypes.byref(te))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te

def Thread32Next(hSnapshot, te = None):
    _Thread32Next = windll.kernel32.Thread32Next
    _Thread32Next.argtypes = [HANDLE, LPTHREADENTRY32]
    _Thread32Next.restype  = bool

    if te is None:
        te = THREADENTRY32()
    te.dwSize = sizeof(THREADENTRY32)
    success = _Thread32Next(hSnapshot, ctypes.byref(te))
    if not success:
        if GetLastError() == ERROR_NO_MORE_FILES:
            return None
        raise ctypes.WinError()
    return te

