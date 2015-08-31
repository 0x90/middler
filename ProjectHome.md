The Middler is a Man in the Middle tool to demonstrate protocol middling attacks.  Led by Jay Beale, the project involves a team of authors including [InGuardians](http://www.inguardians.com) agents Justin Searle and Matt Carpenter.  The Middler is intended to man in the middle, or "middle" for short, every protocol for which we can create code.

In our first alpha release, we released a core built by Matt and Jay, with introductory plug-ins by Justin and InGuardians agent Tom Liston.  It runs on Linux and Mac OS X, with most of the code functional on Windows.

The current codebase is in the beta state, with a full release coming soon, with better documentation (see the wiki), easier installation, and even more plug-ins, at least if Justin has his way!

## Plug-Ins ##

Justin and Tom's first plug-ins were very cool:

  * **plugin-beef.py** - inject the Browser Exploitation Framework (BeEF) into any HTTP requests originating on the local LAN

  * **plugin-metasploit.py** - inject an IFRAME into cleartext (HTTP) requests that loads Metasploit browser exploits

  * **plugin-keylogger.py** - inject a JavaScript onKeyPress event handler to cleartext forms that get submitted via HTTPS, forcing the browser to send the password character-by-character to the attacker's server, before the form is submitted.

Justin has refinements to these on the way, as well as a batch of so-far unreleased modules.

The author team has done a tremendous amount of research, design and pseudo-code work, fleshing out attacks on web-based e-mail systems and social networking sites.  We'll be standing up an external Wiki soon to share more of these ideas, but you can get early details from our slides from Jay and Justin's talks at [Def Con](http://www.defcon.org) and [ShmooCon](http://www.shmoocon.com).

## Dependencies: ##

The Middler depends on the following Python modules:

  * scapy
  * libpcap
  * readline
  * libdnet

Please see the wiki for platform-specific installation instructions.


## People: ##

  * Justin Searle - Co-Author
  * Matt Carpenter - Emeritus Co-Author
  * Tom Liston - Emeritus Co-author
  * Brandon Edwards - Co-Author, focus on Installation and Update MitM
  * Jay Beale - Co-Author and Project Lead

The project will soon be joined by Brandon Edwards, who brings his research on Installation and Update security.


# Special Pre-Announcement: #

Co-author Justin Searle will be teaching a Middling for Penetration Testers class.  You'll learn how to both use and add on to the Middler and other MitM tools.  It promises to be very, very useful.