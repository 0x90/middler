import jjlog
import traffic_capture
import plugins
import proxies

# Items we store, as a kind of global or class variable
interface = ""
redirection_ports = ()

redirected_tcp_ports = []
redirected_udp_ports = []

router_ip = ""

# Are we using sudo to run root commands?
sudo = 0

# IP address we're listening on, defaults to 0.0.0.0
# hostname

# Port we run the HTTP proxy on
# port
