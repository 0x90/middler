#!/usr/bin/env python

def parse_cookies(self, raw_cookie_line):
    """ Parse any Cookie: lines in the request.

        Example:

            parse_cookies("Cookie: GMAIL_AT=xn3j31q5q8ylqcg1163yw9gchigyi6d; gmailchat=some.user@gmail.com/804066; .....")

    """

    # Parsing a string like this:
    #
    # #            Cookie: GMAIL_AT=xn3j31q5q8ylqcg13fyw9gchigyi6d; gmailchat=jay.beale@gmail.com/804066; S=payments=WTqZcq5
    #L9bU:static_files=HxA60P1YyYE:gmail=-zkMnu97hlGeg7NNu7tXGQ:gmail_yj=Qr78OzTSgECwGI1QDvbIfQ:gmproxy=WPfKvb
    #C3a4Q:gmproxy_yj=Ar5Trs-pYMw:gmproxy_yj_sub=KcLOAEX1F4g;
    cookie={}
    raw_cookies=raw_cookie_line.split(r"; ")
    for raw_cookie in raw_cookies:
        # We want the opposite of this:     urllib.urlencode()
        unescaped_cookie=urllib.unquote(raw_cookie)
        #ml.jjlog.debug("Found client trying to send cookie: " + raw_cookie + " decoded version : " + unescaped_cookie)
        #ml.jjlog.debug("Found client trying to send cookie: " + raw_cookie + " decoded version : " + unescaped_cookie)

        equal_pos=unescaped_cookie.index('=')
        # Separate unescaped_cookie into two pieces name= and value
        cookie_name=unescaped_cookie[0:equal_pos]
        cookie_value= unescaped_cookie[equal_pos+1:]
        # BUG/TODO: the previous line might need -1 added to end.
        #ml.jjlog.debug("Found cookie name was " + cookie_name)
        #ml.jjlog.debug("Found cookie value was " + cookie_value)

        # Now remove the equal from name=
        #cookie_name.slice!(-1,1)
        cookie[cookie_name]=cookie_value

        # Let's display this cookie.    But first, let's go a step further if the cookie value contains = signs.
        #
        # Looking to parse a cookie that looks like this:
        #
        # ID=949e33deacfe6ad9:FF=4:LR=lang_en:LD=en:NR=10:TM=1175614973:LM=1210206169:FV=2:GM=1:IG=3:GC=1:S=0uWPvrTxO6BrbAUR;

        has_embedded_cookies_pat = re.compile(r"^([^=]+)=([^:=]+):")
        if has_embedded_cookies_pat.match(cookie_value):
            #ml.jjlog.debug("Found that cookie " + cookie_name + " has embedded cookies inside.")
            # Let's split this intro strings like this:
            #
            # ID=949e33deacfe6ad9:
            # FF=4

            embedded_cookies = cookie_value.split(":")
            for embedded_cookie in embedded_cookies:
                (name,value) = embedded_cookie.split("=")
                #ml.jjlog.debug("Embedded cookie name " + name + " has value " + value)

            #items = embedded_cookies.match(cookie_value).groups()
            #ml.jjlog.debug("Embedded cookie 1: " + items[0] + " = " + items[1] + "\n")

        else:
            pass
            #ml.jjlog.debug("Cookie " + cookie_name + " had value " + cookie_value)

        # check this for Google ID
        # Parse a line like this:
        # gmailchat=jay.beale@gmail.com/839199;

        if cookie_name == "gmailchat":
            developerlog("Current session is user %s\n" % cookie_value)
