#!/usr/bin/env python

# This file is entirely dedicated to providing thread-safe logging capability to the program.

# The thread locks, though, are almost certainly making the proxy slower.

# Let's only log to the debug log file when DEBUG_LOGGING is 1 or higher.
# Let's log to the screen when DEBUG_LOGGING is 2 or higher.

# JLog!

import thread
import time

#global DEVELOPER_LOGGING
DEVELOPER_LOGGING=0
#global DEBUG_LOGGING
DEBUG_LOGGING=0

if DEVELOPER_LOGGING >0:
    dev_log_file =open("developerlog.txt","w")
    dev_log_lock=thread.allocate_lock()

if DEBUG_LOGGING >0:
    debug_log_file =open("debuglog.txt","w")
    debug_log_lock=thread.allocate_lock()

def initialize():
    if DEBUG_LOGGING >0:
        dev_log_file = open("developerlog.txt","w")
        dev_log_lock = thread.allocate_lock()

    if DEVELOPER_LOGGING >0:
        debug_log_file = open("debuglog.txt","w")
        debug_log_lock = thread.allocate_lock()

def stop():
    if DEBUG_LOGGING >0:
        debug_log_file.close()

    if DEVELOPER_LOGGING >0:
        dev_log_file.close()

def jlog_debug_on():
    DEBUG_LOGGING = 1

def jlog_developer_on():
    DEVELOPER_LOGGING = 1

def log(message,add_newline=1):

    print ("%s: %s" % (time.ctime(time.time())) , message )
    if add_newline == 1:
        print "\n"

def developer_log(message,add_newline=1):
    """This writes a log to a file and, if DEVELOPER_LOGGING is set, to stdout."""

    if DEVELOPER_LOGGING >0:

        # Acquire the thread lock associated with logging
        dev_log_lock.acquire()

        # Write to the developer log.
        dev_log_file.write( "%s: %s " % (time.ctime(time.time()),message) )
        if add_newline==1:
            dev_log_file.write("\n")

        # Stop writing to the developer file.
        dev_log_lock.release()

    if DEVELOPER_LOGGING > 1:
        # Log to STDOUT
        log(message,add_newline)

def debug(message,add_newline=1):
    """This writes a log to a file if DEBUG_LOGGING is >0 and also to stdout if DEBUG_LOGGING > 1."""

    if DEBUG_LOGGING >0:

        # Acquire the thread lock associated with logging
        debug_log_lock.acquire()
        # Write to the developer log.
        debug_log_file.write("%s: %s " % (time.ctime(time.time()) , message) )
        if (add_newline==1):
            debug_log_file.write("\n")

        # Stop writing to the developer file.
        debug_log_lock.release()

    if DEBUG_LOGGING >1:
        log(message,add_newline)

def error_log(message,add_newline=1):
    log(message,add_newline)
    # TODO : Add a log file and thread lock for this?
