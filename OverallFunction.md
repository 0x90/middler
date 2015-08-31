# Introduction #

This might be a bit too specific to HTTP, but it's useful nonetheless.


# Details #

We intended the Middler as a proof of concept tool for fully automated man-in-the-middle attacks on both Web applications and thick client programs that use unencrypted HTTP. Much of this stemmed from my frustration when application developers didn't understand the danger of encrypting only the login interaction with the user.  This widened as I started to observe how many processes used HTTP, often without encryption or cryptographic hashing.

So, here's what the Middler should be doing on your system. First, using routines in traffic\_capture.py, it should set the host machine to route IP packets, insert a firewall rule that forces all packets flowing through it that are destined for port 80 to a local port on the machine, and finally start up an ARP spoofing routine to claim the local area network's router's IP address as its own. The local port on which the Middler's HTTP proxy runs defaults to port 80, but can be modified using the -p flag on the command line. The ARP spoofing routine tries to import the scapy module. If it fails, it instead launches the arpspoof command from dsniff, if this is installed. If scapy was present, the Middler uses it to craft the arpspoofing ethernet frames.

Once this is done, the Middler falls into its primary role as a proxy. It analyzes each request's headers, putting these into a data structure that its plug-ins can easily read and modify. It passes this data structure to each plug-in, allowing the plug-in to decide whether it applies to this request and what, if anything, it wants to change in the request, and finally, to indicate it should be the last plug-in to see the request. The Middler then submits the request to the real destination, gets the response and parses that response's header similarly. It passes the response header and data similarly to each plug-in, which again decides whether it wants to modify the response and whether it should be the last to see the response. The Middler then hands the response back to the client.

If you run the Middler on your machine and then use a browser to surf to www.foxnews.com, you'll know that the Middler is working if you end up on CNN's website.