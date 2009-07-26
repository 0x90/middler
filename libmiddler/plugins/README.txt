The sample plugins do the following:

Target URL:		Plugin:			Effect:
===============		======================  ===============================
slashdot.org		iframe_injection	Inject an IFRAME into the top of the page with 
						The Middler's logo
search.debian.org 	metasploit		Inject iframe with Metasploit hook to local install
						(User must set up Metasploit and modify URL, which is
						 currently set to http://172.16.175.134:8000/metasploit)
www.foxnews.com		30x_redirect		Uses a 301 or 307 redirect the browser to cnn.com			

These sample plugins are currently deactivated pending testing:

cisco.com               beef                    Inject script with BeEF hook to local install

www.microsoft.com	redirect_meta		Use HTTP redirection to send browser to www.apple.com



