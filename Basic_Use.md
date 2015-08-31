# Command Line Options #

## Stable Options ##

-i --ip <br>
listen on IP  (default "0.0.0.0" or all IPs)<br>
<br>
-p --port <br>
listen on port  (default "80")<br>
<br>
<h2>Partially Implemented Options</h2>

-s --sslstrip <br>
change HTTPS links to HTTP, while sending data to the server over HTTPS<br>
<br>
-u --url <br>
URL to inject  (currently handled in plugins)<br>
<br>
-a --autopwn <br>
auto-p0wn browsers via Metasploit<br>
<br>
-r --redirect_via_arpspoof <br>
activate ARP spoofing to send out ARP replies claiming the router's IP address<br>
<br>
<h2>Proposed Options</h2>

-v <br>
shows the the proxy request received (including Source IP and target URL)<br>
<br>
-vv <br>
shows the following items:<br>
<ol><li>Proxy Request Received (including Source IP and target URL)<br>
</li><li>Proxy Request Forwarded to Destination<br>
</li><li>Proxy Response Received from Destination<br>
</li><li>Proxy Response Forwarded to Source</li></ol>

-vvv <br>
Same as -vv but includes headers of each request and response<br>
<br>
-vvvv <br>
Same as -vvv but includes payload of each request and response<br>
<br>
<br>
<h1>Example of running Middler</h1>

sudo python middler.py