description = [[
Uploads a local file to a remote web server using the HTTP PUT method.
]]

---
-- @usage
-- nmap -p 80 <ip> --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'
--
-- @output
-- PORT     STATE SERVICE
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-put: /uploads/rootme.php was successfully created
--
-- @args http-put.file - The full path to the local file that should be uploaded to the server
-- @args http-put.url  - The remote directory and filename to store the file to e.g. (/uploads/file.txt)
--

--
--
-- Version 0.1
-- Created 10/15/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth", "discovery", "safe"}

require 'shortport'
require 'stdnse'
require 'http'

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

action = function( host, port )

	local fname, url = stdnse.get_script_args('http-url.file', 'http-put.url')
	if ( not(fname) or not(url) ) then return end 

	local f = io.open(fname, "r")
	if ( not(f) ) then return ("ERROR: Failed to open file: %s"):format(fname) end
	local content = f:read("*all")
	f:close()

	local response = http.put(host, port, url,  nil, content)
	
	if ( response.status == 200 or response.status == 204 ) then
		return ("%s was successfully created"):format(url)
	end

	return ("ERROR: %s could not be created"):format(url)
end
