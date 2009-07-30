#!/usr/bin/env python

from string import find,index,strip
import libmiddler as ml


def parse_sip_uri(sip_uri,only_normalize=0,only_get_caller_id=0):
    """This routine takes in a sip_uri, whether or not surrounded by <>, and
    returns:

        the caller ID (if present) , like "301-555-1212"
        pre-@ SIP ID, like +13015551212
        post-@ SIP client/proxy host,port tuple, like (p.voncp.com,10000)
        a normalized version of the sip uri, like sip:13015914091@p.voncp.com:10000.

    This sip_uri should NOT include the SIP/2.0 trailer present in request methods.

    Here are two examples that use From lines:

    From: "The Middler" <sip:12068837525@69.59.236.139:5060;pstn-params=808282808882>;tag=802356222
    From: <sip:17470848915@proxy01.sipphone.com>;tag=c68b5a63

    Here are two examples that use an INVITE request from the Request line.
    Note that in this case, we'll be handed only the normalized URI, so we shouldn't need
    to use this routine for that.

    INVITE sip:13015914091@75.160.105.73:5061 SIP/2.0
    INVITE sip:+12068837526@proxy01.sipphone.com SIP/2.0
    """

    # Define return variables
    caller_id = ""
    sip_id = ""
    sip_address = ("",5060)
    normalized_sipuri = ""

    # Here's a SIP URI that includes more items than most.
    # From: "301-591-4091"<sip:13015914091@p.voncp.com:10000;user=phone>;tag=c0a800fd-13c5-4a1244f7-19823-2775

    # Start by stripping whitespace
    stripped_uri = strip(sip_uri)
    post_caller_id = stripped_uri

    # Now, let's look for a caller ID string at the start.
    if stripped_uri[0] == '"':

        # Find the second quote.
        end_id = find(stripped_uri[1:],'"')

        if end_id != -1:
            # Caller ID is the part inside the quotes
            caller_id = stripped_uri[1:end_id+1]
            print "caller_id is %s\n" % caller_id
            post_caller_id = stripped_uri[end_id+2:]
            print "post-caller ID is %s\n" % post_caller_id

    if only_get_caller_id:
        return(caller_id)

    # Now, let's find the sip: part, skipping the < if possible.
    sip_colon_location = find(post_caller_id,"sip:")

    if sip_colon_location == -1:
        return(caller_id,"",("",5060),"")

    id_address_and_the_rest = post_caller_id[sip_colon_location+4:]

    #
    # Now we've got something like:
    #
    # 13015914091@p.voncp.com:10000;user=phone>;tag=c0a800fd-13c5-4a1244f7-19823-2775
    #

    # We need to find a semicolon or a > sign.
    first_semicolon = find(id_address_and_the_rest,";")
    greaterthan = find(id_address_and_the_rest,">")

    if first_semicolon == -1 and greaterthan == -1:
        sip_address_end = len(id_address_and_the_rest)
    else:
        sip_address_end = min(first_semicolon,greaterthan)

    id_and_address = id_address_and_the_rest[:sip_address_end]

    # Now we have something like the following, with the :port unnecessary
    #
    # 13015914091@p.voncp.com:10000
    #

    if only_normalize:
        return("sip:%s" % id_and_address)

    try:
        at_location = index(id_and_address,"@")
        sip_id = id_and_address[:at_location]
        sip_address_raw = id_and_address[at_location+1:]

        # The SIP address might have a : in it, allowing alternate port.
        colon = find(sip_address_raw,":")
        if colon == -1:
            sip_host = sip_address_raw
            sip_port = "5060"
            normalized_uri = "sip:%s@%s" % (sip_id,sip_host)

        else:
            sip_host = sip_address_raw[:colon]
            sip_port = sip_address_raw[colon+1:]
            normalized_uri = "sip:%s@%s:%s" % (sip_id,sip_host,sip_port)


        # Put together the sip_address tuple, since this can be passed
        # directly to socket routines.
        sip_address = (sip_host,sip_port)

    except ValueError:
        print "Hit an exception! Argh!!!\n"
        return(caller_id,"",("","5060"),"")

    # Create a normalized URI and return all of this.

    ml.jjlog.developer_log("Split SIP URI %s into SIP id %s and SIP hostname %s on port %s - returning normalized URI %s\n",(sip_uri,sip_id,sip_host,str(sip_port),normalized_uri))
    print("Split SIP URI %s into SIP id %s and SIP hostname %s on port %s - returning normalized URI %s\n",(sip_uri,sip_id,sip_host,str(sip_port),normalized_uri))
    return(caller_id,sip_id,(sip_host,sip_port),normalized_uri)

def normalize_sip_uri(sip_uri,only_normalize=1):
    return parse_sip_uri(sip_uri,only_normalize=1)

def get_caller_id(from_rvalue_sip_uri):
    return parse_sip_uri(from_rvalue_sip_uri,only_normalize=0,only_get_caller_id=1)

def modify_caller_id(from_rvalue_sip_uri,new_caller_id="The Middler"):

    """This routine takes in the rhs of a From: header line and returns one with the caller-ID changed.

    "+12068837526" <sip:12068837525@69.59.236.139:5060;pstn-params=808282808882>;tag=802356222

    becomes:

    "+14433267298" <sip:12068837525@69.59.236.139:5060;pstn-params=808282808882>;tag=802356222

    This sip_uri should NOT include the SIP/2.0 trailer present in request methods.

    """

    # Define return variables
    new_from_rvalue = ""

    # Here's a SIP URI that includes more items than most.
    # From: "301-591-4091"<sip:13015914091@p.voncp.com:10000;user=phone>;tag=c0a800fd-13c5-4a1244f7-19823-2775

    # Start by stripping whitespace
    stripped_uri = strip(from_rvalue_sip_uri)
    post_caller_id = stripped_uri

    # Now, let's look for a caller ID string at the start.
    if stripped_uri[0] == '"':

        # Find the second quote.
        end_id = find(stripped_uri[1:],'"')

        if end_id != -1:
            # Caller ID is the part inside the quotes
            caller_id = stripped_uri[1:end_id+1]
            print "caller_id was %s\n" % caller_id
            post_caller_id = stripped_uri[end_id+2:]
            #print "post-caller ID is %s\n" % post_caller_id

            # Change the caller_id
            new_from_rvalue = ' "%s" %s' % (new_caller_id,post_caller_id.rstrip("\r\n"))
        else:
            ml.jjlog.debuglog("ERROR - could not find a caller ID string in two quotes in %s" % sip_uri)
            return from_rvalue_sip_uri
    else:
        ml.jjlog.debuglog("Did not find a caller ID string in two quotes in %s" % sip_uri)
        return from_rvalue_sip_uri


if __name__ == "__main__":
    from libmiddler.api.parse_uris import *

#    while True:
 #       test = input("Input a SIP URI: ")
  #      uri_touple = parse_sip_uri(test)
   #     print "Parses into these values: %s." % str(uri_touple)
