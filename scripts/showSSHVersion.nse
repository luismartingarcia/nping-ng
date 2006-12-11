id = "Stealth SSH version"

description = "Connects to an SSH server, queries the version string and echos it back. This tends to result\
in the scanning attempt not being logged by the ssh daemon on the target."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"demo"}

portrule = function(host, port) 
	if 
		port.service == "ssh"
		and port.protocol == "tcp" 
		and port.state == "open" 
	then
		return true
	else
		return false
	end
end

action = function(host, port)
	local result, socket

	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)

	result = ""
	socket = nmap.new_socket()

	try(socket:connect(host.ip, port.number))

	result = try(socket:receive_lines(1));
	try(socket:send(result))
	try(socket:close())

	return "" .. string.gsub(result, "\n", "") 
end

