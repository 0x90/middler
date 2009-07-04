#!/bin/bash

echo "Trying request talking directly to proxy."
cat <<ENDL | nc 192.168.112.129 80
GET / HTTP/1.1
Host: www.slashdot.org

ENDL

