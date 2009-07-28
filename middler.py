#!/usr/bin/env python
import libmiddler as ml
import signal
import sys,os
import threading

# Add The Middler's module namespace to the path.
sys.path.append(os.curdir + os.sep)

# Make a dirty global variable to hold child pids that we should remember to clean up
ml.child_pids_to_shutdown = []

############################################################################################################
# Parse command-line options                                                                                                                                                             #
############################################################################################################

def parseCommandLineFlags():

    from optparse import OptionParser
    parser = OptionParser(usage="%prog [-p port] ", version="%prog 1.0")

    parser.add_option("-p", "--port", dest="port",
                                    help="HTTP should listen on this port",default="80")
    parser.add_option("-A", "--arpspoof_off", action="store_true", dest="toggle_arpspoof_off", default=False,
                                    help="turn off ARP spoofing, so The Middler doesn't broadcast ARP replies claiming the router's IP address")
    (options,args)=parser.parse_args()

    return (options,args)

###################################
# Main non-class Code starts here.
###################################


# First, parse out command-line options

if __name__ == '__main__':


    ##############################
    # Parse command-line options #
    ##############################

    (options,args) = parseCommandLineFlags()

    ml.toggle_arpspoof_off = options.toggle_arpspoof_off
    ml.port = int(options.port)

    ml.hostname = "0.0.0.0"

    ###################
    # Signal handling #
    ###################

    # Define a signal handler so we can make sure we close the log files.
    def handle_signal_term(signum,frame):

        # TODO-High: cleanly deactivate ARP spoofing

        # Deactivate any ARP spoofing
        # deactivate_arpspoof()

        # Turn off the firewalling/routing
        ml.jjlog.debug("Deactivating routing/firewall-based packet fu.")
        ml.traffic_capture.stop()

        # Close up the log files.
        ml.jjlog.debug("Closing log files.\n")
        ml.jjlog.stop()

        # Kill off any children we've left around, generally from ARP spoofing.
        for pid in ml.child_pids_to_shutdown:
            print "Killing off PID %d\n" % pid
            os.kill(pid,9)

        # Wait for any processes we started to finish
        for pid in ml.child_pids_to_shutdown:
            os.waitpid(pid,0)

        exit(0)


    # Catch normal kill command
    signal.signal(signal.SIGTERM, handle_signal_term)
    # Catch Ctrl-C
    signal.signal(signal.SIGINT, handle_signal_term)

    # Initialize Logging - open files for writing and create thread locks.
    ml.jjlog.initialize()

    # Announce ourselves
    print "=================================="
    print("The Middler - HTTP and SIP Edition")
    print "==================================\n\n"

    # Start up the firewalling and routing to    send traffic to us.
    #from ml.Middler_Firewall import startRedirection,stopRedirection
    ml.traffic_capture.start()

    # Activate the DNS spoofing?
    #os.spawnl(os.P_NOWAIT,r"/Users/jay/BFF_DNS.pl","")

    #
    # Activate the ARP spoofing.
    #

    #
    # The middle_the_net module contains functions to target and MitM the LAN
    #
    # First, define what interfaces we need to ARPspoof.
    #
    #if ml.toggle_arpspoof:

        # Now, launch a thread/process to ARPspoof the network.
        # We wrote this as a thread, but we might write it as a process later.
        # Doing the latter requires working with shared memory and command channels.
        #ml.set_up_arpspoofing(target_host="ALL",interface="defaultroute",impersonated_host="defaultrouter")

    #
    # Set up a data structure to hold the threads that are running our servers
    #

    proxy_threads = []

    #
    # Start up the multi-threaded HTTP proxy
    #

    ml.jjlog.debug("Activating HTTP proxy\n")

    # Import HTTP proxy modules
    import libmiddler.proxies
    import libmiddler.proxies.http
    import libmiddler.proxies.http.http_proxy

    # Stage an HTTP proxy on port 80
    # Start up HTTP proxies on TCP port 80
    for tcp_port in (ml.port,):
        server = libmiddler.proxies.http.http_proxy.ThreadedTCPServer((ml.hostname,ml.port), libmiddler.proxies.http.http_proxy.Middler_HTTP_Proxy)
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.setDaemon(True)
        proxy_threads.append(server_thread)
        server_thread.start()
        print "HTTP proxy loop running in thread %s listening on port %d" % (server_thread.getName(),ml.port)

    #
    # SIP Proxies
    #

    # Import SIP proxy modules
    import libmiddler.proxies.sip
    import libmiddler.proxies.sip.sip_proxy

    # Now start up a SIP UDP proxy on 5060, 5061, 10000, and 64064
    for udp_port in 5060, 5061, 10000, 64064:
        sip_udp_proxy = libmiddler.proxies.sip.sip_proxy.ThreadedUDPServer((ml.hostname,udp_port), libmiddler.proxies.sip.sip_proxy.Middler_SIP_UDP_Proxy)
        sip_udp_thread = threading.Thread(target=sip_udp_proxy.serve_forever)
        sip_udp_thread.setDaemon(True)
        proxy_threads.append(sip_udp_thread)
        sip_udp_thread.start()
        print "SIP UDP proxy running in thread %s listening on port %d" % (sip_udp_thread.getName(),udp_port)
    #
    # Future feature: TCP proxy too, implementing the TCP and UDP versions as subclasses of a wider class.
    #

    #
    # Primary difference is having to read Content-Length.
    #

    # Now start up a SIP TCP proxy on 5060 and 5061
    #SIP_tcp_proxy = libmiddler.proxies.sip.sip_proxy.ThreadedTCPServer((ml.hostname,5060), libmiddler.proxies.sip.sip_proxy.MiddlerSIPTCPProxy)
    #sip_tcp_thread = threading.Thread(target=SIP_tcp_proxy.serve_forever)
    #sip_tcp_thread.setDaemon(True)
    #proxy_threads.append(sip_tcp_thread)
    #sip_tcp_thread.start()
    #print "SIP TCP proxy running in thread: ", sip_tcp_thread.getName()


    while True:
        pass
    # We shouldn't ever reach this line, since the signal handler should do this.
    ml.jjlog.stop()
