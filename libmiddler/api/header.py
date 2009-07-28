# This file contains API helper routnes for checking and changing HTTP headers.

import libmiddler as ml

headertest_stdmatch = (("Content-type","text/html"),)

def headertest(header, match = headertest_stdmatch):
    ''' Determine whether each HTTP header line named contains the named specific case-insensitive substring.
        match is a tuple/list of Header 2-tuples.  Each tuple contains a left hand side string and a right
        hand side substring.
    '''

    count = 0
    for test in range(len(match)):
        for current in range(len(header)):
            # TODO-High: Change the first compare (lhs) to a string equality check.
            if ( (header[current][0].lower() == match[test][0].lower()) and (header[current][1].lower().find(match[test][1].lower()) > -1)):
                count = count + 1
                break

    if count == len(match):
        return True
    else:
        return False




def old_headertest(header, match = headertest_stdmatch):
    ''' Deprecated version b/c logic is flawed - remove once we confirm we're not dependent on it.
    - Jay
    '''

    # Subtle bug below - because the left hand side (name of the header) line is specified as a
    # substring match, it's possible that multiple header lines might match for a given lhs
    # pattern.  Combining this with the speed-ineffecient choice not to break out of the
    # (current) loop on a match, you can have a double match on one line that cancels out a
    # non-match on another line.

    count = 0
    for current in range(len(header)):
        for test in range(len(match)):
            if (((header[current][0].lower().find(match[test][0].lower())) > -1) and (header[current][1].lower().find(match[test][1].lower()) > -1)):
                count = count + 1

    if count == len(match):
        return True
    else:
        return False

def headerfix(header, key, value):
    ''' Change HTTP Header key to value in place in header.

        Example: ml.api.header.headerfix(header,"Expires","Fri, 01 Jan 1990 00:00:00 GMT")

    '''

    for current in range(len(header)):
        if(header[current][0].lower().find(key.lower()) > -1):
            header.pop(current)
            header.insert( current, (key,value) )
            ml.jjlog.debug("Changed header line %s" % (str(current)) )

def headerget(header, headername):
    ''' Get the value of first HTTP header line <headername>.

        Note that this won't work well on cookies if the cookie you're looking for is
        not on the first cookie line.

        Example: header.headerfix(header,"Expires")
    '''

    key = headername.lower()

    for current in range(len(header)):
        if(header[current][0].lower().find(key) > -1):
            return header[current][1]

    return("HeaderNotFound")
