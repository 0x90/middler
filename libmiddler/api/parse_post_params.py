#!/usr/bin/env python

# parse_any_post_params() - Parse the data in a POST request.
def parse_any_post_params():
    """Parse the data in a POST request."""

    # Now let's parse the rest of the request if any exists.

    while line == "":
        line = self.rfile.readline()
        #ml.jjlog.debug(line)

        #ml.jjlog.debug(line,0)
        if client_headers["method"] == "POST":
            #ml.jjlog.debug("We have a post - TODO: parse the params!\n")
            if re.match("&",line):
                params = line.split("&")
                for param in params:
                    if re.match("=",param):
                        (variable,value) = param.split("=")
                        #ml.jjlog.debug("POST data: %s=%s" % (variable,value))
                    else:
                        ml.jjlog.debug("POST data: %s" % param)
            else:
                ml.jjlog.debug("POST data: %s" % line)

        modified_request = modified_request + line
    # end while line == "":
