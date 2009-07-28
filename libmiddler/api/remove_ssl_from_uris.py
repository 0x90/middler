#!/usr/bin/env python

#
# string &remove_ssl(text) takes a string and changes all of the https links into http links
#
def remove_ssl(text):
    """ remove_ssl(text) takes a chunk of text and changes all of the https links
    into http links, adding a pattern (currently /secure3 so as to place state
    in the link itself.

    We use this to allow Middler to identify requests that it should issue with
    SSL, while keeping the client side of the connection in straight HTTP.
    """

    # We want to change links that looks like this:
    #
    # https://host/foo
    #
    # to ones like this:
    #
    # http://host/secure3/foo
    #
    # We will then change any links they click on back to the original form
    # so that we talk to the servers through an encrypted connection and thus
    # have access to the pages we're loading.

    removessl_pat=re.compile(r"https://([^\\]+)(/.*)")
    newtext = removessl_pat.sub(r"http://\1/secure3\2",text)
    return newtext
