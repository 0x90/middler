From the SIP RFC, RFC 3261 (http://www.ietf.org/rfc/rfc3261.txt)

      The Content-Length header field value is used to locate the end of
      each SIP message in a stream.  It will always be present when SIP
      messages are sent over stream-oriented transports.

So we need to operate both a UDP and TCP proxy on 5060.

Vonage uses UDP, while Gizmo uses TCP.