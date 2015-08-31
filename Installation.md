# Introduction #

This page describes how to install The Middler on each operating system, including its dependencies.

The Middler requires Python 2.6.

The Middler depends only on core Python modules, except to generate its own ARP spoofing packets.

To generate ARP spoofing packets, you have two options: install dsniff or install scapy, along with scapy's dependencies.  All of the instructions below, except the Easy Source Install, assume that you want to use scapy.

# Dependencies #

If you elect to let The Middler use dsniff to arpspoof, you need only install dsniff.

If you want The Middler to use scapy, you need to install the following scapy dependencies, all Python modules:

  * scapy
  * libpcap
  * readline
  * libdnet  (known as libdumbnet in Debian and Ubuntu because of namespace conflict)

To use the plugin-metasploit.py plug-in, you'll also need the [the Metasploit Framework](http://www.metasploit.com/framework/).

To use the plugin-beef.py plug-in, you'll need the [BeEF Browser Exploitation Framework](http://www.bindshell.net/tools/beef/).

# Easy Installation From Source with Dsniff #

1. Install Python 2.6.x.

2. Download and install dsniff to allow The Middler to ARP spoof.

2a. To let The Middler run dsniff's arpspoof, get the latest source from [dsniff's page](http://monkey.org/~dugsong/dsniff/).  Here's a direct link to [dsniff 2.3 (stable)](http://monkey.org/~dugsong/dsniff/dsniff-2.3.tar.gz).  On Mac OSX, we found the 2+ year old beta, [dsniff-2.4b1.tar.gz Dsniff 2.4 Beta 1](http://monkey.org/~dugsong/dsniff/beta/dsniff-2.4b1.tar.gz) to work better.

3. On Linux, install the Netfilter Python module.  This dependency is going away.  You can download [this stable source](http://opensource.bolloretelecom.eu/files/python-netfilter-0.5.6.tar.gz) or do a Subversion checkout.


# Harder Installation from Source with Scapy #

1. Install Python 2.6.

2. To make The Middler generate its own ARP spoofing packets via scapy, download the latest source from [scapy's web page](http://www.secdev.org/projects/scapy/).  The latest release should be available directly via [Scapy-Latest](http://www.secdev.org/projects/scapy/files/scapy-latest.zip).

3. Install Python modules

  * libpcap
  * readline
  * libdnet  (known as libdumbnet in Debian and Ubuntu because of namespace conflict)


# Ubuntu/Debian/BT4 Linux Installation #

To install the necessary Middler dependencies on Ubuntu or Debian Linux, run:

```
sudo aptitude install libdumbnet-dev python-libpcap python-beautifulsoup python-scapy
svn co https://svn.bolloretelecom.eu/opensource/python-netfilter/trunk/ python-netfilter
cd python-netfilter
sudo python setup.py install
cd ..
```

Then download Middler with:

```
svn checkout http://middler.googlecode.com/svn/trunk/ middler-read-only  
```

If you would like to play with the Metasploit or BEEF plugins, you'll need to install that software as well.  To install Metasploit, you'll need its dependencies.  Here's the command we used to install these on Ubuntu Linux:

```
sudo aptitude install ruby libruby rdoc libyaml-ruby libzlib-ruby libopenssl-ruby libdl-ruby libreadline-ruby libiconv-ruby rubygems
```

Of course, you'll want to download and install [Metasploit](http://www.metasploit.com).

# Mac OS X Installation #

To install the necessary Python modules on OS X Leopard (10.5), we downloaded Python 2.6.x from Python.org, then used the source installation methods above.  MacPorts has scapy, but gives it a massive number of unnecessary dependencies that take forever to compile.

To use the plugin-metasploit.py plug-in, you'll want to install the Metasploit Framework.  We used the instructions on [Metasploit's Mac OS X Instalation page.](http://trac.metasploit.com/wiki/Metasploit3/InstallMacOSX)

As it recommends, we used Ruby's Gems system, which lets you very easily fetch Ruby modules and their dependencies.  If you already have MacPorts installed, you might want to install Ruby and Gems through MacPorts.  Here are commands to do this, including the version correction for Rails that the Metasploit Framework page suggests.

```
port install ruby rb-rubygems 
gem install readline
gem install -v=1.2.2 rails
```