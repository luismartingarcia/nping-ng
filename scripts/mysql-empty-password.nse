description = [[
Checks for MySQL servers with an empty password for <code>root</code> or
<code>anonymous</code>.
]]

---
-- @output
-- 3306/tcp open  mysql
-- | mysql-empty-password:  
-- |   anonymous account has empty password
-- |_  root account has empty password

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

require 'shortport'
require 'stdnse'
require 'mysql'

-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/23/2010 - v0.2 - revised by Patrik Karlsson, added anonymous account check
-- Revised 01/23/2010 - v0.3 - revised by Patrik Karlsson, fixed abort bug due to try of loginrequest

portrule = shortport.port_or_service(3306, "mysql")

action = function( host, port )

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local result, response = {}, nil
	local users = {"", "root"}
	
	-- set a reasonable timeout value
	socket:set_timeout(5000)
	
	for _, v in ipairs( users ) do
		try( socket:connect(host.ip, port.number, "tcp") )	
		response = try( mysql.receiveGreeting( socket ) )
		status, response = mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, v, nil, response.salt )	
		if response.errorcode == 0 then
			table.insert(result, string.format("%s account has empty password", ( v=="" and "anonymous" or v ) ) )
			if nmap.registry.mysqlusers == nil then
				nmap.registry.mysqlusers = {}
			end
			nmap.registry.mysqlusers[v=="" and "anonymous" or v] = ""
		end
		socket:close()
	end
	
	return stdnse.format_output(true, result)	

end
