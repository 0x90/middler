# This file contains API helper routnes for checking and changing HTTP headers.

headertest_stdmatch = (("Content-type","text/html"),)

def headertest(header, match = headertest_stdmatch):
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
	developer_log("In headerfix() changing key %s to value %s" % key,value)
	debug_log("Header before fixing %s line is %s" % key,header)
	for current in range(len(header)):
		if(header[current][0].lower().find(key.lower()) > -1):
			header.pop(current)
			header.insert( current, (key,value) )
			debug_log("Changed header line %s" % str(current) )


def headerget(header, key):
	for current in range(len(header)):
		if(header[current][0].lower().find(key) > -1):
			return header[current][1]
