#!/usr/bin/python
import urllib2
from BeautifulSoup import BeautifulSoup
import support.header as header

### CHANGE AS NEEDED
request_match = (("Host","debian.com"),)
response_match = (("Content-type","TEXT/HTML"),)
redirect_url = "http://www.takogrill.com"



### FUNCTION TO MANIPULATE CLIENT REQUEST
def doRequest(session, request_header, data):
  changed = 0
  stop = 0
  if header.headertest(request_header, request_match):

    ### MANIPULATE DATA
    changed = 1
    stop = 1
    header.headerfix(request_header, "Host", redirect_url + '\r\n')
    print("User request URL has been rewritten to " + redirect_url)

    ### RETURN DATA
  return(request_header, data, changed, stop)



### FUNCTION TO MANIPULATE SERVER RESPONSE
def doResponse(session, request_header, response_header, data):
  changed = 0
  stop = 0
  return(response_header, data, changed, stop)

