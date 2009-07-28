#!/usr/bin/env python

import libmiddler as ml
# Copyright 2009 Jay Beale
# Licensed under GPL v2

from httplib import *
from socket import *
from string import *
import os, signal, SocketServer, select, sys, Cookie
import re, urllib,time
import threading, thread
import urlparse

#### Globals

keep_gzip_in_requests = 0
port = 80

# Process ID's for any processes we fork
child_pids_to_shutdown = []
toggle_arpspoof = False

####################################################################################################
# Network interface code
####################################################################################################

#
# Define both substring matches and regular expressions to match client
# request request_headers against.
#
prefix = {}
len_prefix = {}
prefix["host"] = "Host"
prefix["authorization"] = "Authorization"
prefix["useragent"] = "User-Agent"
prefix["cookie"] = "Cookie"
prefix["connection"] = "Connection"
prefix["proxyconnection"] = "Proxy-Connection"
prefix["acceptencoding"] = "Accept-Encoding"
prefix["content-length"] = "Content-length"


# Pre-compute the lengths of the prefix (substring matches) to speed parsing.
# While we're at it, let's create a tuple of the keys here so we can
# change the line matching routine later to loop over the available
# prefixes more quickly.

client_header_prefixes = tuple(prefix.keys())

for item in client_header_prefixes:
    len_prefix[item] = len(prefix[item])

#
#
# The Session class is for storing information about a given
# person/process that we learn while proxying one connection
# so as to use that information while handling other connections.
#
# Among other things, this is where we keep note of someone's username
# in an application.  When we get the GUI going, this is where we'll
# track what actions we've cued for their user on their next session.
#

class Sessions(dict):
    def getSession(self, source_ip):
        session = self.get(source_ip, None)
        if session == None:
            session = { 'source_ip' : source_ip }
            self[source_ip] = session
        return session

# Check sys.modules['middler']'s directory for a plugins/ directory.

PLUGINS = []
if (not PLUGINS or len(PLUGINS) == 0):

    ###### This code loads the fileparsers into the PLUGINS list
    parserdir = "%s%splugins"%(os.sep.join(sys.modules['libmiddler'].__file__.split(os.sep)[:-1]), os.sep)
    #parserdir = "%s%splugins"%(os.sep.join(sys.modules['libmiddler'].__file__.split(os.sep)[:-1]), os.sep) + "/enabled"
    ml.jjlog.debug(">>plugindir: %s<<"%parserdir)

    filename = None
    for filename in  os.listdir(parserdir):
        try:
        # Add any file in the active plugins directory that ends in .py and doesn't
        # start with _ to our list of plugins.

            if (len(filename) > 3 and filename[0] != "_" and filename[-3:] == ".py"):
        #ml.jjlog.debug(">>Trying to load plugin from libmiddler.plugins.enabled.%s"%filename[:-3] )
                PLUGINS.append(__import__("libmiddler.plugins.%s"%filename[:-3], None, None, "libmiddler.plugins"))
        except:
            ml.jjlog.debug("Error loading plugin %s"%filename)
            x,y,z = sys.exc_info()
            sys.excepthook(x,y,z)
            pass

# If we haven't found the plugins/ directory yet, check the current directory
# for a plugins/ directory.

if (not PLUGINS or len(PLUGINS) == 0):

    ###### This code loads the fileparsers into the PLUGINS list
    #ml.jjlog.debug( os.path.abspath(os.curdir)
    parserdir = "./plugins"
    ml.jjlog.debug(">> Had to set plugin directory relative to current dir - plugindir: %s<<"%parserdir)
    filename = None
    try:
        for filename in  os.listdir(parserdir):
            try:
                if (len(filename) > 3 and filename[0] != "_" and filename[-3:] == ".py"):
                    PLUGINS.append(__import__("libmiddler.plugins.%s"%filename[:-3], None, None, "libmiddler.plugins"))
            except:
                ml.jjlog.debug("Error loading plugin %s"%filename)
                x,y,z = sys.exc_info()
                sys.excepthook(x,y,z)
                pass
    except OSError:
        pass

###########################################################
# Networking code starts here.                                                        #
###########################################################

#
# Tell SocketServer.ThreadingTCPServer to release the ports
# it binds to more quickly upon exit.
#

class PluginSaysDontSend(Exception):
    def __init__(self, headers, data):
        self.headers = headers
        self.data = headers

#class MiddlerThreadTCPServer(SocketServer.ThreadingTCPServer):
#class MiddlerThreadTCPServer(SocketServer.TCPServer):
class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


#
# Set up the HTTP proxy - we'll have more protocols soon.
#

class MiddlerHTTPProxy(SocketServer.StreamRequestHandler):
#class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    # Set up a sessions() data structure for tracking information about
    # each target user, indexed by IP address.

    sessions = Sessions()

    def __init__(self, request, client_address, server):
        self.client_headers = {}
        self.current_user = MiddlerHTTPProxy.sessions.getSession(client_address)
        #ml.jjlog.debug( (request, client_address, server, dir(self))
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

    ####################################################################################################
    # Plugin Architecture functions are found here - very important to understand                                            #
    ####################################################################################################

    # This function runs through all plugins that have subscribed, passing each
    # the request headers and data, receiving both back, possibly modified along
    # with notification as to whether the plugin changed anything and if the
    # plugin requires that no other plugin receive a chance to make changes
    # before we hand the data back to the user.

    def doRequest(self, session, request_headers, data):
        global PLUGINS
        for plugin in PLUGINS:
            try:
                ml.jjlog.debug("executing plugin %s" % plugin)
                request_headers, data, changed, stop = plugin.doRequest(session, request_headers, data)
                if stop:
                    break
            except PluginSaysDontSend, e:
                raise e
            except Exception, msg:
                print "ERROR in plugin %s: %s"%(repr(plugin), repr(msg))
        return (session, request_headers, data)

    # This function runs through all plugins that have subscribed, passing each
    # the response headers and data, receiving both back, possibly modified along
    # with notification as to whether the plugin changed anything and if the
    # plugin requires that no other plugin receive a chance to make changes
    # before we hand the data back to the user.    This function also gives each
    # plugin a copy of the request headers, allowing the plugins to know what
    # contributed to this response.    In particular, the request's method/URL are
    # likely very critical here.

    # TODO-Med: Figure out if we should be handing the request data (like POST
    # data) to the plugins.

    def doResponse(self, session, request_headers, response_headers, data):
        global PLUGINS
        for plugin in PLUGINS:
            try:
                response_headers, data, changed, stop = plugin.doResponse(session, request_headers, response_headers, data)
                if stop:
                    break
            except PluginSaysDontSend, e:
                raise e
            except Exception, msg:
                print "ERROR in plugin %s: %s"%(repr(plugin), repr(msg))
        ml.jjlog.debug("returning from doResponse")
        return (session, response_headers, data)


    ####################################################################################################
    # Main handler functions
    ####################################################################################################

    # handle() - handles one client connection intended for a web server.
    def handle(self):
        """Handles one client connection intended for a web server."""

        # close_request: tracks whether the browser has asked to close the
        # connection when we're done servicing this request.
        #print self
        close_requested=0

        while close_requested == 0:
            ml.jjlog.debug("Started a new thread to handle connection from %s!" % self.client_address[0])

            #test_header = "HTTP/1.1 200 OK" + "Date: Sat, 09 Aug 2008 09:44:35 GMT" + "Server: Apache/1.3.41 (Unix) mod_perl/1.31-rc4" + "Connection: close" + "Content-Type: text/html; charset=iso-8859-1" + "\n\nfoo\n"

            desthostname = "" # var: desthostname stores the server name we're trying to contact.
            modified_request = "" # var: modified_request stores the modified request, which is the same as the real request except when we make a change.
            ## var: client_headers{} stores relevant header values, to take effort off plug-in authors.
            #client_headers =    {}

            #
            # Store variables about things we want to modify:
            #


            inject_status_code = 0    # var: inject_status_code - should we inject a new status code on next request?

            # Status code message we'd like to inject, like:
            #
            # HTTP/1.1 307 Temporary Redirect
            # ...
            # with location field:
            #
            # Location: http://mail.google.com/mail/

            status_code_to_inject = ""

            # Location we'd like to inject, with 301 (permanent) or 307 (temporary)
            #location_to_inject = ""


            # Content-Length handling - if we modify POST data, we need to recalculate the content length.
            # var: recalculate_content_length - Track whether we need to recalculate the content length.
            # TODO: Should we track the current content_length offset with each change?
            recalculate_content_length = 0
            suppress_content_length = 1


            # var: need_to_do_this_over_ssl keeps track of whether we're proxying a
            # request to a link that we previously converted from https:// to http://.
            need_to_do_this_over_ssl=0

            ###########################################################################
            # Parse HTTP request headers
            ###########################################################################

            # Start by parsing the client headers until we hit a blank line signaling
            # that those headers are over.

            # TODO-Low: move the header line-specific code here into anonymous
            #                     routines, referenced by a hash like the prefix{} and
            #                     len_prefix{} hashes.

            # TODO-Med: remove the repeated modified_request concat lines, replacing
            #                     with logic that simply does this unless the routine would
            #                     not have.    If it would not have, let's have it just blank the
            #                     line.

            #print("self.rfile is the following kind of object %s\n" % str(type(self.rfile)) )
            line = ""
            try:
                line = self.rfile.readline()
                #sys.stdout.write(line)
                #sys.stdout.write(r"\r\n")
            except:
                print "ERROR: first readline() on the request failed!\n"
                self.finish()

            #
            try:
                method, url, HTTPprotocol = line.split(' ',2)

            except ValueError:
                print ("ERROR: Failure condition while separating out the parts of line by spaces - method was %s, URL was %s, line was:%s\n" % (method,url,line) )
                exit(1)


            request_headers = [ ("Request",line) ]

            try:
                while True:
                    line = self.rfile.readline()
                    if line in ("\r\n" ,"\n"):
                        break
                    header, value = line.split(": ",1)
                    request_headers.append((header,value))
                #sys.stdout.write(line)
            #print "done reading request_headers!"
            except:
                ml.jjlog.debug("Probably just finished reading request header")

            #### Handle Header-analysis

            # Now for the rest of the request_headers (the official ones)
            length = len(request_headers)
            index = 1
            while index < length:
                #print index
                #print request_headers[index]
                header, value = request_headers[index]
                if lower(header) == lower(prefix["host"]):
                    desthostname = value.strip()
                    #modified_request = modified_request + line

                elif lower(header) == lower(prefix["connection"]):
                    connection = value
                    self.client_headers["connection"] = connection
                    if connection == "Close":
                        close_requested = 1
                            #ml.jjlog.debug("Encountered a Connection: close from browser - it doesn't want keepalive.")

                elif lower(header) == lower(prefix["proxyconnection"]):
                    proxyconnection = value

                    self.client_headers["proxyconnection"] = proxyconnection
                    if proxyconnection.strip().lower() != "keep-alive":
                        ml.jjlog.debug("Debug: stripping out a Proxy-Connection - are you sure you're not pointing your browser at this intentionally?")

                        # Strip this line out so we don't tell the server we're using a proxy.
                        #
                        # So the following line is commented out.
                        # modified_request = modified_request + line

                elif lower(header) == lower(prefix["content-length"]):
                    self.client_headers["content-length"] = value

                elif lower(header) == lower(prefix["acceptencoding"]):
                    acceptencoding = value
                    #self.client_headers["acceptencoding"] = acceptencoding
                    # TODO: Make this a user option

                    # Remove any acceptance of gzip encoding.
                    if not keep_gzip_in_requests:
                        request_headers.pop(index)
                        length -= 1
                    #modified_request = modified_request + line

                index += 1

            port = 80
            ml.jjlog.debug("%s is requesting %s:%s" % (self.client_address[0], desthostname, port))
            print("%s is requesting %s:%s" % (self.client_address[0], desthostname, port))

            try:
                if method == "POST":
                    request_data = self.rfile.read(int(self.client_headers["content-length"]))

                    #ml.jjlog.debug("done reading POST data: \n%s"%request_data)
                else:
                    request_data = ""
                    #ml.jjlog.debug("done reading data! ")
            finally:
                self.rfile.close()

            self.current_user, request_headers, request_data = self.doRequest(self.current_user, request_headers, request_data)
            ml.jjlog.debug("returned from doRequest")

            ###########################################################################
            # Send request and parse HTTP response headers
            ###########################################################################

            #response_to_send_to_client=""
            #server_headers = {}
            response=""
            modified_headers = []

            # Open a connection to the desired server and send request
            #send_request(desthostname,port,method,url,request_headers)

            # TODO-low: should probably use the host from here too...
            if url[0:7] == "http://":
               url_obj = urlparse.urlsplit(url)
               path = url_obj.path
               if url_obj.query:
                  path += "?" + url_obj.query
               if url_obj.fragment:
                  path += "#" + url_obj.fragment
            else:
               path = url
            #print "URL: ", url
            #print "Path: ", path

            try:
                port = 80
                ml.jjlog.debug("Connecting HTTP to: %s:%d\n" % (desthostname,port))
                j=HTTPConnection("%s:%d" % (desthostname,port) )
                j.putrequest(method,path,skip_host=True,skip_accept_encoding=True)

                # Switch in the original headers.

                for header in request_headers[1:]:
                    lvalue = header[0]
                    lvalue = lvalue.capitalize()
                    # Handle \r and \n's getting added to later header fields.
                    rvalue = header[1].rstrip("\r\n")
                    #print ("%s: %s" % (lvalue,rvalue) )
                    j.putheader(lvalue,rvalue)
                    #print "Just inserted header %s: %s" % ( lvalue,rvalue)

                j.endheaders()
                j.send(request_data)

                # Now get a response and take the parsing for free!
                response_object=j.getresponse()
                if response_object.status in [ 200,301,302,303,307 ]:
                    #ml.jjlog.debug("Request to http://%s/%s returned response code %d" %(desthostname,url,response_object.status ))
                    pass
                elif response_object.status in [ 500 ]:
                    ml.jjlog.debug("Request to http://%s/%s returned response code %d" %(desthostname,url,response_object.status ))

                else:
                    ml.jjlog.debug("Request to http://%s/%s returned response code %d" %(desthostname,url,response_object.status ))

            except:
                ml.jjlog.debug("Connection failed to host %s\n" % desthostname)
                self.finish()
                break

                #ml.jjlog.debug("Just sent modified request: \n%s" % modified_request)
                #ml.jjlog.debug("Just sent modified request:\n%s" % modified_request)

            #
            # Now parse the data from the server
            #

            # Parse the response
            modified_response=""

            # Now parse one line at a time
            content_type_is_image = 0

            # Build a response string.
            http_version = "HTTP/%s.%s" % (str(response_object.version)[0],str(response_object.version)[1])
            response_code_line = "%s %s %s" % (http_version,str(response_object.status),str(response_object.reason))
            #print ("Got response code %s\n" % response_object.status)
            #print ("Response code line is %s\n" % response_code_line)
            ml.jjlog.debug("response_code_line is %s" % response_code_line)

            # Let's put the response code on top, allowing the plugins to see and modify
            # the response code.

            response_headers = []
            response_headers.append( ["Response",response_code_line] )

            # Now add on the rest of the response headers.
            unordered_headers = response_object.getheaders()
            for header_idx in xrange(0, len(unordered_headers)):
                try:
                    hdr = unordered_headers[header_idx]
                    header, value = hdr
                    if lower(header) == "set-cookie":
                       cookies = response_object.msg.getallmatchingheaders('Set-Cookie')
                       for x in cookies:
                          header, value = x.split(": ",2)
                          value = value.rstrip("\n\r")
                          response_headers.append([header.capitalize(),value])
                    else:
                       response_headers.append([header.capitalize(),value])
                    
                except:
                    print "Header parsing failing.\n"
                    self.finish()

            # And store the data in the page.
            response_data = response_object.read()

            # Temporary code for seeing if the difference in sites is the ret characters
            firstret = response_data.find('\n')
            if firstret >= 0 :
                if response_data[firstret-1] == '\r':
                    ml.jjlog.debug("For site %s, newlines included \\r!" % desthostname)

            ml.jjlog.debug("\nbefore plugin, response headers are %s\n\n" % response_headers)
            self.current_user, response_headers, response_data = self.doResponse(self.current_user, request_headers, response_headers, response_data)
            ml.jjlog.debug("after plugins, response headers are %s\n\n" % response_headers )

            # TODO-med: Make SSL changes happen prior to this? Via a plugin or engine?
            # Caught the bug!!!!
            #
            # modified_response_temp was built without adding the rets to the first line!!!!

            rets = "\r\n"
            #response_code_line = ( "%s%s" % (response_headers[0][1] , rets) )
            modified_response_temp = []

            # Remove the first item from response_headers, since it's our Response Code and reason
            # psuedo-header.  We can make this the first line, but it needs to have only the rvalue.
            if http_version == "HTTP/1.0":
               modified_response_temp.append(response_headers.pop(0)[1] + rets)
            else:
               modified_response_temp.append(response_headers.pop(0)[1])


            seen_content_length = 0
            for header_idx in xrange(0,len(response_headers)):
                if response_headers[header_idx][0] == "X-cnection":
                   continue
                if lower(response_headers[header_idx][0]) == "transfer-encoding":
                   if lower(response_headers[header_idx][1]) == "chunked":
                      response_headers[header_idx][0] = "Content-length"
                      response_headers[header_idx][1] = len(response_data)
                      seen_content_length = 1
                   else:
                      continue
                if lower(response_headers[header_idx][0]) == "content-length":
                   if seen_content_length:
                      continue
                modified_response_temp.append("%s: %s%s"% (response_headers[header_idx][0],response_headers[header_idx][1],rets))
            #print "modified response is %s" % modified_response_temp
            modified_response_temp.append(rets)     #rets is the *identified* bytes used as CRLF
            modified_response_temp.append(response_data)
            modified_response = "".join(modified_response_temp)


            # Send the response back to the client
            #ml.jjlog.debug("Preparing to send modified response to client: %s" % modified_response)
            try:
                self.wfile.write(modified_response)
                self.wfile.flush()

                ##### TODO-high: This is experimental... remove if it breaks stuff.
                close_requested = 1
                self.wfile.close()
            except:
                self.wfile.close()
                self.finish()
                #self.wfile.close()
                #self.rfile.close()


    # Complete the connection.
    def finish(self):

        self.wfile.close()
        self.rfile.close()
