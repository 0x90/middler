#!/usr/bin/python
import urllib2
import re
import libmiddler.api.header as header
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

  target = "www.cnn.com"
  request_match = (("Host",target),)

  if header.headertest(request_header,request_match):

      # We could make sure only to do this if the browser was getting a web page.
      response_match = (("Content-type","TEXT/HTML"),)
      if header.headertest( response_header,response_match ):

          # Check the response code line.
          response_code_line = response_header[0][1]
          (protover,response_code,reason) = response_code_line.split(" ")

          print ("Response code line had these elements --%s-- --%s-- --%s\n" % (protover,response_code,reason) )

          # Make sure we are only doing this on a 200 message.
          if response_code != "200":
              return(response_header, data, changed, stop)


          # Change the response code to a 30x redirect.

          # Choose one of these two.
          response_code = 307
          reason = "Temporary Redirect\n"
          #response_code = 301
          #reason = "Moved Permanently"

          # Does this need a new line?
          header.headerfix(response_header,"Response",("%s %s %s" % (protover,response_code,reason)) )
          print ("Changed status code to:\n%s %s %s--" % (protover,response_code,reason))

          # Check if there is a Location header already?
          # TODO: make a routine that inserts a new header after a specific line.
          if header.headerget("Location") and redirect_url:
              header.headerfix( response_header, "Location", redirect_url + "\n")
          else:
              response_header.append( ("Location",redirect_url + "\n") )

          # We have changed the header and we don't want any other plugins to touch it.
          # TODO: Decide on how to do priority/dependencies/ordering so redirects go first.

          changed = 1
          stop = 1

  return(response_header, data, changed, stop)