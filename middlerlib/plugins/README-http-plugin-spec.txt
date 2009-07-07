"""
Middler Core will basically do this for each connection both directions:
  Read in Headers
  Read in Data
  Pull session information (per-client?  per-session?)
  Hand off information to plugins
  Put together Header and Data Response.




Implement the following:
  def doRequest(session, header, cookies, data):
    
  def doResponse(session, header, cookies, data):
    
Return the header and data and whether to continue to other plugins.
"""

VER = 1.0

class AbstractModule:
    def doRequest(session, request_header, data):
        return (request_header, data, changed, stop)

    def doResponse(session, request_header, response_header, data):
        return (response_header, data, changed, stop)


