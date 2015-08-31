# (Higher Bandwidth) Getting Set Up Using the Samurai WTF Bootable Linux Distribution #
  1. Download the latest copy of Samurai-WTF at samurai.inguardians.com
  1. Boot Samurai-WTF from the live CD or from a virtual environment like VMware.
  1. Install Middler's dependencies by opening a terminal and running: <br> <code>sudo aptitude install libdumbnet-dev python-libpcap python-beautifulsoup python-scapy</code>
<ol><li>Install Middler by running: <br> <code>svn checkout http://middler.googlecode.com/svn/trunk/ middler-read-only</code>
</li><li>Install dsniff so we can spoof ARP tables on victim machines (This functionality will be included in Middler within the next few weeks): <br> <code>sudo aptitude install dsniff</code>
</li><li>Since middler needs to listen on port 80, shut down apache: <br> <code>sudo /etc/init.d/apache2 stop</code></li></ol>

<h1>Getting Set Up On Your Own Machine</h1>
#. Install Python 2.6.x.<br>
<br>
#. Download and install dsniff to allow The Middler to ARP spoof.<br>
<br>
#. To let The Middler run dsniff's arpspoof, get the latest source from dsniff's page. Here's a direct link to dsniff 2.3 (stable). On Mac OSX, we found the 2+ year old beta, dsniff-2.4b1.tar.gz Dsniff 2.4 Beta 1 to work better.<br>
<br>
#. On Linux, install the Netfilter Python module. This dependency is going away. You can download this stable source or do a Subversion checkout.<br>
<br>
#  Install Middler by running: <br> <code>svn checkout http://middler.googlecode.com/svn/trunk/ middler-read-only</code>


<h1>Playing with Middler</h1>
<ol><li>Move into the Middler's directory: <br> <code>cd middler-read-only</code>
</li><li>Start up Middler with: <br> <code>sudo ./middler.py</code>
</li><li>Choose a victim computer (or start a second VM to pick on)<br>
</li><li>On the victim machine, verify the gateway's MAC address is being spoofed: <br> <code>arp -n</code>
</li><li>On the victim machine, open a browser and surf to www.slashdot.org