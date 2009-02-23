#!/usr/bin/env python

# JLog!

import thread

#global DEVELOPER_LOGGING
DEVELOPER_LOGGING=1
#global DEBUG_LOGGING
DEBUG_LOGGING=1

dev_log_file =open("developerlog.txt","w")
debug_log_file =open("debuglog.txt","w")
dev_log_lock=thread.allocate_lock()
debug_log_lock=thread.allocate_lock()

def initialize_logging():
  dev_log_file = open("developerlog.txt","w")
  debug_log_file = open("debuglog.txt","w")
  dev_log_lock = thread.allocate_lock()
  debug_log_lock = thread.allocate_lock()

def stop_logging():
  dev_log_file.close()
  debug_log_file.close()

def log(message,add_newline=1):

  print message
  if add_newline == 1:
    print "\n"

def developer_log(message,add_newline=1):
  """This writes a log to a file and, if DEVELOPER_LOGGING is set, to stdout."""

  # Acquire the thread lock associated with logging
  dev_log_lock.acquire()
  # Write to the developer log.

  dev_log_file.write(message + "\n")

  # Stop writing to the developer file.
  dev_log_lock.release()

  if DEVELOPER_LOGGING:
    # Log to STDOUT
    log(message,add_newline)

def debug_log(message,add_newline=1):
  """This writes a log to a file and, if DEBUG_LOGGING is set, to stdout."""

  # Acquire the thread lock associated with logging
  debug_log_lock.acquire()
  # Write to the developer log.
  debug_log_file.write(message)
  # Stop writing to the developer file.
  debug_log_lock.release()

  if DEBUG_LOGGING:
    log(message,add_newline)

def debug_log_no_newline(message):
  if DEBUG_LOGGING:
    log(message,0)

def error_log(message,add_newline=1):
  log(message,add_newline)
  # TODO : Add a log file and thread lock for this
