id = "MS Windows shell"

description = "If port 8888 is open and it echos a specific string then we\
might have found an open MSWindows shell."

author = "Diman Todorov <diman.todorov@gmail.com>"

license = "See nmaps COPYING for licence"

categories = {"backdoor"}

portrule = function(host, port) 
	local decision
	if 
		(	port.number == 8888
			or port.service == "auth")
		and port.protocol == "tcp" 
		and port.state == "open"
	then
		decision = true
	else
		decision = false
	end

	return decision
end

action = function(host, port)
	local status = 0
	local result = ""

	local client_ident = nmap.new_socket()

	client_ident:connect(host.ip, port.number)

	status, result = client_ident:receive_bytes(4096)

	client_ident:close()

	if string.match(result, "Microsoft Windows") then
		return "Possible open windows shell found."
	end
end

