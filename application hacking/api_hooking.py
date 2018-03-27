#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Python Hacking Basic
# NOTICE : only for STUDY purpose!!!!
# NOTICE : unauthorized hacking is ILLEGAL!!!
# March 2018

"""
[application_hacking]
- API Hooking
"""

import sys
import utils
from pydbg import *
from pydbg.defines import *


ORIGINAL_PATTERN = "like"
CHANGED_PATTERN = "hate"
PROCESS_NAME = "notepad.exe"


def replace_string(dbg, args):
    global ORIGINAL_PATTERN, CHANGED_PATTERN
    buf = dbg.read_process_memory(args[1], args[2])   

    if ORIGINAL_PATTERN in buf:
        print "[APIHooking] Before : {}".format(buf)
        buf = buf.replace(ORIGINAL_PATTERN, CHANGED_PATTERN)
        dbg.write_process_memory(args[1], buf)
        print "[APIHooking] After : {}".format(dbg.read_process_memory(args[1], args[2]))        

    return DBG_CONTINUE


def api_hooking(api_hooker, process_name):
    is_process = False

    for(pid, name) in api_hooker.enumerate_processes():
        if name.lower() == process_name:
            is_process = True
            hooks = utils.hook_container()

            api_hooker.attach(pid)
            print ".. Saves a process handle in self.h_process of pid[%d]" % pid

            hook_address = api_hooker.func_resolve_debuggee("kernel32.dll", "WriteFile")

            if hook_address:
                hooks.add(api_hooker, hook_address, 5, replace_string, None)
                break
            else:
                print "[Error] : couldn't resolve hook address"
                sys.exit(-1)

    if is_process:
        print ".. Waiting for occurring debugger event"
        api_hooker.run()
    else:
        print "[Error] : There in no process [{}]".format(process_name)
        sys.exit(-1)


"""
api hooking starts..
"""
if __name__ == '__main__':
    # Construct pydbg object and set ready for hooking
    debugger = pydbg()

    print('.. API Hooking Start')
    api_hooking(debugger, PROCESS_NAME)
