#!/usr/bin/env python


# This code is currently unused in Middler.

# It was the beginning of some special treatment for the user agent line in the HTTP request's header.
# This will be more useful in the future, particularly for applying different behavior or exploits for
# different browsers.

#module ParseProxy:

def parse_useragent(user_agent):
  current_user = {}
  client_headers = {}

  if not current_user.has_key("UserAgent"):

    client_headers["user_agent"]=user_agent
    current_user["UserAgent"]=user_agent
    # Now parse out the specific browser
    firefox_pat=re.compile(r".*Firefox/(\d+\.\d+\.\d+).*")
    iphone_safari_pat=re.compile(r"Mozilla/(\d+\.\d+) \(iPhone; U; CPU iPhone OS (\d+_\d+) like Mac OS X\;\s*\w+-\w+.*\) AppleWebKit/([\d\.]+)  \(KHTML, like Gecko\) Version/([\d\.]+) Mobile/(\w+) Safari/([\d\.]+)")

    if firefox_pat.match(user_agent):
      # Example of catching Firefox in use:
      # Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14
      browser_type="Firefox"
      browser_version_set=firefox_pat.match(user_agent).groups()
      browser_version=browser_version_set[0]
      current_user["browser_type"] = browser_type
      current_user["browser_version"] = browser_version
      print "Found that user has Firefox version",browser_version,"\n"
    elif iphone_safari_pat.match(user_agent):
      # Example of catching iPhone in use:
      #
      # User-Agent: Mozilla/5.0 (iPhone; U; CPU iPhone OS 2_0 like Mac OS X;
      # en-us) AppleWebKit/525.18.1 (KHTML, like Gecko) Version/3.1.1
      # Mobile/5A347 Safari/525.20
      browser_type="iPhone Safari"
      browser_version_set=iphone_safari_pat.match(user_agent).groups()
      browser_version=browser_version_set[4]
      current_user["browser_type"] = browser_type
      current_user["browser_version"] = browser_version
      # TODO: Figure out which version changes the most or is used in OSVDB for tracking
      print "Found that user has iPhone Safari version",browser_version,"\n"
    #elif apple_pub_sub.match(useragent):
    #  User-Agent: Apple-PubSub/65.1.1

    # User-Agent: KNewsTicker v0.2
    # User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_3; en-us) AppleWebKit/525.18 (KHTML, like Gecko) Version/3.1.1 Safari/525.20

    else:
      developer_log ("UserAgent string we cannot yet parse:" + user_agent,"\n")
  return current_user

  #def parse_useragent (line)

    #unless $current_user["UserAgent"]
      #md=/^User-Agent: (.*)/.match(line)
      #user_agent_raw_string=md[1].chomp
      ##client_headers["user_agent"]=user_agent_raw_string
      #$current_user["UserAgent"]=user_agent_raw_string
      ## Now parse out the specific browser
      #case user_agent_raw_string
      #when / Firefox\//
        ## Catch Firefox:
        ## Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.14) Gecko/20080404 Firefox/2.0.0.14
        #browser_type="Firefox"
        #browser_version=/Firefox\/(\d+\.\d+\.\d+)/.match(user_agent_raw_string)[1].chomp
        #$current_user["browser_type"] = browser_type
        #$current_user["browser_version"] = browser_version
        #puts "Found Firefox version #{browser_version}\n"
        #STDOUT.flush
      ##else
      ##  developer_log "UserAgent string we cannot yet parse: #{user_agent_raw_string}\n"
      #end # when / Firefox\//
    #end # unless $current_user["UserAgent"]
  #end # def parse_useragent
