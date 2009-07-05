#!/usr/bin/env python

# This file contains the functions that make the current system intercept traffic.

# sys and os are both necessary
import sys
import os

# We need to log
from JLog import *

#######################
# Variable definitions
#######################

# Fix the operating_system variable to "nyd" for "not yet determined."

operating_system = "nyd"

####################################################################################################
### Firewall/routing setup, to route packets and capture connections                               #
####################################################################################################
  

def redirectIPFWstart():
  """This functions starts up the ipfw forwarding so that as this machine routes traffic, it redirects port 80 traffic to itself."""

  # Set up firewall to grab port 80 traffic flowing through this machine and send it
  # to the proxy.

  # For debugging where you can't run the program as root, or if you just like your security like that, you could
  # run the Middler's HTTP proxy on an unprivileged port, and use the rule below that's appropriate to your O/S to
  # redirect traffic to that port.
  #
  # OSX: ipfw add 1000 fwd 127.0.0.1,8080 tcp from any to 127.0.0.1 dst-port 80 in via lo0

  # Run ipfw list, so we can look for a rule that starts with 01000
  ipfw_cmd=os.popen("/sbin/ipfw list","r")
  ipfw_lines=ipfw_cmd.readlines()
  ipfw_cmd.close()

  found_line=0
  for line in ipfw_lines:
    if re.match(r"^01000 fwd 127\.0\.0\.1\,80 tcp from any to any dst-port 80 in via lo0",line):
      found_line=1

  if not found_line:
    ipfw_modify=os.popen("/sbin/ipfw add 1000 fwd 127.0.0.1,80 tcp from any to any dst-port 80 in via lo0")

  found_line

def redirectIPFWstop():
  
  # Run ipfw list, so we can look for a rule that starts with 01000
  ipfw_cmd=os.popen("/sbin/ipfw list","r")
  ipfw_lines=ipfw_cmd.readlines()
  ipfw_cmd.close()

  found_line=0
  for line in ipfw_lines:
    if re.match(r"^01000 fwd 127\.0\.0\.1\,80 tcp from any to any dst-port 80 in via en1",line):
      found_line=1

  if found_line:
    ipfw_modify=os.popen("/sbin/ipfw del 1000")

  found_line

def redirectIPTablesStart():
  
  # Add a rule called MIDDLERNAT that forces any traffic destined for port 80 to go instead
  # to the local port 80 on this system.
  
  os.system("iptables -t nat -N MIDDLERNAT")
  os.system("iptables -t nat -I MIDDLERNAT -p tcp --dport 80 -j REDIRECT --to-ports 80")
  os.system("iptables -t nat -A PREROUTING -j MIDDLERNAT")

def redirectIPTablesStop():

  # TODO-Medium: write a routine to find the jump to the MIDDLERNAT rule first, so we can entirely remove
  # all traces of the MIDDLERNAT rule instead of just rendering it ineffective.
  os.system("iptables -t nat -D MIDDLERNAT 1")

  ##############################
  # Packet Routing             #
  ##############################

def startRedirection():

  # Activate forwarding on the operating system kernel.
  debug_log("Activating forwarding\n")
  
  # Check if we're on OS X.
  if sys.platform == r"darwin":
    
    # Activate forwarding on Darwin via sysctl
    os.system(r"sysctl -w net.inet.ip.forwarding=1")
    debug_log("On OSX - just set net.inet.ip.forwarding.")

    # Set up the firewall
    redirectIPFWstart()
    
  # Next check if we're on Linux
  elif sys.platform == r"linux2":
    
    # Activate packet forwarding via proc
    os.system(r"echo 1 >/proc/sys/net/ipv4/ip_forward")
    debug_log("On Linux - just set /proc/sys/net/ipv4/ip_forward to 1.")

    redirectIPTablesStart()
    
  # Next check if we're on Windows (Cygwin)
  elif sys.platform[:3] == r"win":
    print "ERROR: routing and network redirection code does not yet run on Windows"
    
  else:
    debug_log("Could not detect operating system or The Middler cannot yet support firewalling and routing on it.")

def stopRedirection():
  
  debug_log("Entered stopRedirection()")
 
  if sys.platform == "darwin":
    
    # Turn off the packet mangling / port redirecton
    redirectIPFWstop()
    debug_log("Just deactivated OSX firewall-based port redirection.")
  
    # Deactivate IPv4 forwarding on Darwin via sysctl
    os.system(r"sysctl -w net.inet.ip.forwarding=0")
    debug_log("Just deactivated IPv4 routing.")
    
  elif sys.platform == "linux2":

    # Turn off the packet mangling / port redirection.
    redirectIPTablesStop()
    debug_log("Just deactivated firewall-based port redirection.")

    # Deactivate packet forwarding via proc
    os.system(r"echo 0 > /proc/sys/net/ipv4/ip_forward")
    debug_log("Just deactivated IPv4 routing.")

  elif sys.platform[:3] == "win":
    print "ERRROR: routing redirection cannot be halted on Windows yet..."
  
  else:
    debug_log("Could not detect operating system or The Middler cannot yet support firewalling and routing on it.")
    debug_log(sys.platform)