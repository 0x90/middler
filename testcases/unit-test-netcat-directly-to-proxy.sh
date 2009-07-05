#!/bin/bash

echo "Trying request talking directly to proxy."
cat <<ENDL | nc 127.0.0.1 80
GET / HTTP/1.1
Host: search.debian.org

ENDL

