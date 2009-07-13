#!/usr/bin/python
import urllib2
import re
import libmiddler.api.header as header
#import libmiddler.api.register_http_plugin as register_http_plugin

debug_request = 0
debug_response = 0

### FUNCTION TO MANIPULATE CLIENT REQUEST
def doRequest(session, request_header, data):
  changed = 0
  stop = 0

  if debug_request:
      i=1
      for header_line in request_header:
        print ("Request header line %d has lvalue %s and rvalue %s" % (i,header_line[0],header_line[1]) )
        i=i+1

  return(request_header, data, changed, stop)

### FUNCTION TO MANIPULATE SERVER RESPONSE
def doResponse(session, request_header, response_header, data):
  changed = 0
  stop = 0

  if debug_response:
      i=1
      for header_line in response_header:
        print ("Response header line %d has lvalue %s and rvalue %s" % (i,header_line[0],header_line[1]) )
        i=i+1

  return(response_header, data, changed, stop)
