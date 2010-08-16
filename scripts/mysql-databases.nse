description = [[
Attempts to list all databases on a MySQL server.
]]

---
-- @args mysqluser The username to use for authentication. If unset it
-- attempts to use credentials found by <code>mysql-brute</code> or
-- <code>mysql-empty-password</code>.
-- @args mysqlpass The password to use for authentication. If unset it
-- attempts to use credentials found by <code>mysql-brute</code> or
-- <code>mysql-empty-password</code>.
--
-- @output
-- 3306/tcp open  mysql
-- | mysql-databases:  
-- |   information_schema
-- |   mysql
-- |   horde
-- |   album
-- |   mediatomb
-- |_  squeezecenter

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

require 'shortport'
require 'stdnse'
require 'mysql'

dependencies = {"mysql-brute", "mysql-empty-password"}

-- ripped from ssh-hostkey.nse
-- openssl is required for this script
if not pcall(require,"openssl") then
	portrule = function() return false end
  	action = function() end
  	stdnse.print_debug( 3, "Skipping %s script because OpenSSL is missing.",
  	    SCRIPT_NAME)
  	return;
end


-- Version 0.1
-- Created 01/23/2010 - v0.1 - created by Patrik Karlsson

portrule = shortport.port_or_service(3306, "mysql")

action = function( host, port )

	local socket = nmap.new_socket()
	local catch = function() socket:close()	end
	local try = nmap.new_try(catch)
	local result, response, dbs = {}, nil, {}
	local users = {}
	local nmap_args = nmap.registry.args
	local status, rows

	-- set a reasonable timeout value
	socket:set_timeout(5000)

	-- first, let's see if the script has any credentials as arguments?
	if nmap_args.mysqluser then
		users[nmap_args.mysqluser] = nmap_args.mysqlpass or ""
	-- next, let's see if mysql-brute or mysql-empty-password brought us anything
	elseif nmap.registry.mysqlusers then
		-- do we have root credentials?
		if nmap.registry.mysqlusers['root'] then
			users['root'] = nmap.registry.mysqlusers['root'] 
		else
			-- we didn't have root, so let's make sure we loop over them all
			users = nmap.registry.mysqlusers
		end
	-- last, no dice, we don't have any credentials at all
	else
		stdnse.print_debug("No credentials supplied, aborting ...")
		return
	end

	--
	-- Iterates over credentials, breaks once it successfully recieves results
	--
	for username, password in pairs(users) do

		try( socket:connect(host, port) )

		response = try( mysql.receiveGreeting( socket ) )
		status, response = mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, username, password, response.salt )

		if status and response.errorcode == 0 then
			status, rows = mysql.sqlQuery( socket, "show databases" )
			if status then
				for i=1, #rows do
					-- cheap way of avoiding duplicates
					dbs[rows[i]['Database']] = rows[i]['Database']
				end
				
				-- if we got here as root, we've got them all
				-- if we're here as someone else, we cant be sure
				if username == 'root' then	
					break
				end
			end
		end
		socket:close()
	end

	for _, v in pairs( dbs ) do
		table.insert(result, v)
	end

	return stdnse.format_output(true, result)	

end
