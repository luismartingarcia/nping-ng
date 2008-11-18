description = [[
Attempts to find the owner of an open TCP port by querying an auth
(identd - port 113) daemon which must also be open on the target system.
]]
---
--@output
-- 21/tcp   open     ftp       ProFTPD 1.3.1
-- |_ auth-owners: nobody
-- 22/tcp   open     ssh       OpenSSH 4.3p2 Debian 9etch2 (protocol 2.0)
-- |_ auth-owners: root
-- 25/tcp   open     smtp      Postfix smtpd
-- |_ auth-owners: postfix
-- 80/tcp   open     http      Apache httpd 2.0.61 ((Unix) PHP/4.4.7 ...)
-- |_ auth-owners: dhapache
-- 113/tcp  open     auth?
-- |_ auth-owners: nobody
-- 587/tcp  open     submission Postfix smtpd
-- |_ auth-owners: postfix
-- 5666/tcp open     unknown
-- |_ auth-owners: root


author = "Diman Todorov <diman.todorov@gmail.com>"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "safe"}

portrule = function(host, port)
	local auth_port = { number=113, protocol="tcp" }
	local identd = nmap.get_port_state(host, auth_port)

	return identd ~= nil
		and identd.state == "open"
		and port.protocol == "tcp"
		and port.state == "open"
end

action = function(host, port)
	local owner = ""

	local client_ident = nmap.new_socket()
	local client_service = nmap.new_socket()

	local catch = function()
		client_ident:close()
		client_service:close()
	end

	local try = nmap.new_try(catch)

	try(client_ident:connect(host.ip, 113))
	try(client_service:connect(host.ip, port.number))

	local localip, localport, remoteip, remoteport =
        	try(client_service:get_info())

	local request = port.number .. ", " .. localport .. "\n"

	try(client_ident:send(request))

	owner = try(client_ident:receive_lines(1))

	if string.match(owner, "ERROR") then 
		owner = nil
	else
		owner = string.match(owner, "USERID : .+ : (.+)\n", 1)
	end

	try(client_ident:close())
	try(client_service:close())

	return owner
end
