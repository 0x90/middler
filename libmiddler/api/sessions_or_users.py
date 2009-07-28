#!/usr/bin/env python

#
# The HTTP_Sessions class is for storing information about a given
# person/process that we learn while proxying one connection
# so as to use that information while handling other connections.
#
# Among other things, this is where we keep note of someone's username
# in an application.  When we get the GUI going, this is where we'll
# track what actions we've cued for their user on their next session.
#
# The next step is to make HTTP_Sessions and SIP_Sessions both subclasses
# of a Sessions class, allowing us to share data from all protocols.
#

# This file is not yet used.

class HTTP_Sessions(dict):
    def __init__(self,source_ip):
        session = { 'source_ip' : source_ip }
        self[source_ip] = session

    def getSession(self, source_ip):
        session = self.get(source_ip, None)
        if session == None:
            session = { 'source_ip' : source_ip }
            self[source_ip] = session
        return session
