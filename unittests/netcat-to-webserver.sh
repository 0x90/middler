#!/bin/bash

echo "Trying request without talking directly to the proxy"
cat <<ENDL | nc search.debian.org 80
GET / HTTP/1.1
Host: search.debian.org

ENDL

