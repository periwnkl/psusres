#!/usr/bin/env python
# coding: utf-8
# psusres: a tool to suspend/resume a process
from __future__ import print_function
from optparse import OptionParser
from winapi import *

def PauseResumeThreadList(dwOwnerPID, bSuspendThread):
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwOwnerPID)
    if hThreadSnap == INVALID_HANDLE_VALUE:
        return
    
    te32 = Thread32First(hThreadSnap)
    if te32:
        while True:
            if te32.th32OwnerProcessID == dwOwnerPID:
                hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID)
                if bSuspendThread:
                    print("Suspending Thread 0x{0:04X}".format(te32.th32ThreadID))
                    SuspendThread(hThread)
                else:
                    print("Resuming Thread 0x{0:04X}".format(te32.th32ThreadID))
                    ResumeThread(hThread)
                CloseHandle(hThread)
            te32 = Thread32Next(hThreadSnap)
            if not te32:
                break
    
    CloseHandle(hThreadSnap)

def ProcessList():
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe32 = Process32First(hProcessSnap)
    if (pe32):
        while True:
            print('PID\t', pe32.th32ProcessID, '\t', pe32.szExeFile, sep='')
            pe32 = Process32Next(hProcessSnap)
            if not pe32:
                break
    CloseHandle(hProcessSnap)

def main():
    usage = 'usage: %prog [options] PID'
    parser = OptionParser(usage)
    parser.add_option('-s', '--suspend', action='store_true', dest='suspend',
        help='suspend a specified process')
    parser.add_option('-r', '--resume', action='store_false', dest='suspend',
        help='resume a specified process')
    options, args = parser.parse_args()
    
    if options.suspend is None:
        parser.print_help()
        print()
        ProcessList()
    elif len(args) == 0:
        parser.print_help()
    else:
        try:
            pid = int(args[0])
        except:
            print("Invalid PID number:", args[0])
        else:
            PauseResumeThreadList(pid, options.suspend)
    
    return

if __name__ == '__main__':
    main()
