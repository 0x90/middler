#!/bin/bash

echo "Trying request without talking directly to the proxy"
cat <<ENDL | nc www.slashdot.org 80
GET / HTTP/1.1
Host: www.slashdot.org

ENDL

