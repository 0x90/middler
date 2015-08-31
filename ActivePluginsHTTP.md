# Introduction #

The Middler achieves its HTTP-based attacks primarily through plugins.  Some of our plugins are still in alpha mode, but those below are in beta or better.

# Details #

These plugins are currently "active" - they are in beta or have been released:

  * **plugin\_iframe\_injection.py** - Injects an IFRAME in the page that loads a 150x103 pixel version of The Middler logo.
  * **plugin\_30x\_redirect.py** - redirects requests for one page to another, currently www.cnn.com.

These are the sites on which these plugins trigger:

  * **plugin\_iframe\_injection.py** - http://slashdot.org
  * **plugin\_30x\_redirect.py** - http://www.foxnews.com/