#!/usr/bin/python
import libmiddler as ml
import libmiddler.api.header as header


### FUNCTION TO MANIPULATE SERVER RESPONSE
def doRequest(session, request_header, response_header, data):
    changed = 0
    stop = 0
    i = 1

    # Lets change all incoming calls to a specific phone number that have caller ID set to +12068837526
    # to use different caller ID, say, +14433267298

    # Unfortunately, incoming requests may not use the correct IP address.  For now, let's
    # just search on the SIP username in the To.


    # We're only looking for INVITE requests.
    if not self.is_request:
        return(request_header, data, changed, stop)

    (method,sipuri,version) = header.headerget(request_header,"Request").split(" ",2)
    if method != "INVITE":
        return(request_header, data, changed, stop)

    # We're only looking to target a specific user.
    target = "sip:17470848985"
    targetlen = len(target)
    if sipuri[0:targetlen] != target:
        return(request_header, data, changed, stop)

    # OK - we've got the right user.

    # If the caller-ID is present, let's change it to another phone number.
    from_rvalue = header.headerget(request_header,"From")
    if from_rvalue != "HeaderNotFound":
        if self.get_caller_id(from_rvalue) != "":
            new_from_rvalue = self.modify_caller_id(from_rvalue)
            ml.api.header.headerfix(request_header,"From",new_from_rvalue)

            # We have changed the header and we don't want any other plugins to touch it.
            # TODO: Decide on how to do priority/dependencies/ordering so redirects go first.

            changed = 1
            stop = 1

    return(request_header, data, changed, stop)


### FUNCTION TO MANIPULATE CLIENT REQUEST
def doResponse(session, request_header, data):
    changed = 0
    stop = 0

    return(response_header, data, changed, stop)
