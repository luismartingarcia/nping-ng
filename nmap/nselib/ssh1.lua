--- Functions for the SSH-1 protocol.
-- \n\n
-- This module also contains functions for formatting key fingerprints.
-- @author Sven Klemm <sven@c3d2.de>
-- @copyright See nmaps COPYING for licence

module(... or "ssh1",package.seeall)

local bin = require "bin"
local bit = require "bit"
local math = require "math"
local stdnse = require "stdnse"
local openssl = require "openssl"

--- Fetch a SSH-1 host key.
--@param host Nmap host table.
--@param port Nmap port table.
--@return A table with the following keys: "exp", "mod", "bits", "key_type",
--"fp_input", "full_key", "algorithm", and "fingerprint".
fetch_host_key = function(host, port)
  local socket = nmap.new_socket()
  local status

  status = socket:connect(host.ip, port.number)
  if not status then return end
  -- fetch banner
  status = socket:receive_lines(1)
  if not status then socket:close(); return end
  -- send our banner
  status = socket:send("SSH-1.5-Nmap-SSH1-Hostkey\r\n")
  if not status then socket:close(); return end

  local data, packet_length, padding, offset
  status,data = socket:receive()
  socket:close()
  if not status then return end

  offset, packet_length = bin.unpack( ">i", data )
  padding = 8 - packet_length % 8
  offset = offset + padding

  if padding + packet_length + 4 == data:len() then
    -- seems to be a proper SSH1 packet
    local msg_code,host_key_bits,exp,mod,length,fp_input
    offset, msg_code = bin.unpack( ">c", data, offset )
    if msg_code == 2 then -- 2 => SSH_SMSG_PUBLIC_KEY
      -- ignore cookie and server key bits
      offset, _, _ = bin.unpack( ">A8i", data, offset )
      -- skip server key exponent and modulus
      offset, length = bin.unpack( ">S", data, offset )
      offset = offset + math.ceil( length / 8 )
      offset, length = bin.unpack( ">S", data, offset )
      offset = offset + math.ceil( length / 8 )

      offset, host_key_bits = bin.unpack( ">i", data, offset )
      offset, length = bin.unpack( ">S", data, offset )
      offset, exp = bin.unpack( ">A" .. math.ceil( length / 8 ), data, offset )
      exp = openssl.bignum_bin2bn( exp )
      offset, length = bin.unpack( ">S", data, offset )
      offset, mod = bin.unpack( ">A" .. math.ceil( length / 8 ), data, offset )
      mod = openssl.bignum_bin2bn( mod )

      fp_input = mod:tobin()..exp:tobin()

      return {exp=exp,mod=mod,bits=host_key_bits,key_type='rsa1',fp_input=fp_input,
              full_key=exp:todec()..' '..mod:todec(),algorithm="RSA1",
              fingerprint=openssl.md5(fp_input)}
    end
  end
end

--- Format a key fingerprint in hexadecimal.
fingerprint_hex = function( fingerprint, algorithm, bits )
  fingerprint = stdnse.tohex(fingerprint,{separator=":",group=2})
  return ("%d %s (%s)"):format( bits, fingerprint, algorithm )
end

--- Format a key fingerprint in Bubble Babble.
fingerprint_bubblebabble = function( fingerprint, algorithm, bits )
  local vowels = {'a','e','i','o','u','y'}
  local consonants = {'b','c','d','f','g','h','k','l','m','n','p','r','s','t','v','z','x'}
  local s = "x"
  local seed = 1

  for i=1,#fingerprint+2,2 do
    local in1,in2,idx1,idx2,idx3,idx4,idx5
    if i < #fingerprint or #fingerprint / 2 % 2 ~= 0 then
      in1 = fingerprint:byte(i)
      idx1 = (bit.band(bit.rshift(in1,6),3) + seed) % 6 + 1
      idx2 = bit.band(bit.rshift(in1,2),15) + 1
      idx3 = (bit.band(in1,3) + math.floor(seed/6)) % 6 + 1
      s = s .. vowels[idx1] .. consonants[idx2] .. vowels[idx3]
      if i < #fingerprint then
        in2 = fingerprint:byte(i+1)
        idx4 = bit.band(bit.rshift(in2,4),15) + 1
        idx5 = bit.band(in2,15) + 1
        s = s .. consonants[idx4] .. '-' .. consonants[idx5]
        seed = (seed * 5 + in1 * 7 + in2) % 36
      end
    else
      idx1 = seed % 6 + 1
      idx2 = 16 + 1
      idx3 = math.floor(seed/6) + 1
      s = s .. vowels[idx1] .. consonants[idx2] .. vowels[idx3]
    end
  end
  s = s .. 'x'
  return ("%d %s (%s)"):format( bits, s, algorithm )
end

--- Format a key fingerprint into a visual ASCII art representation.
-- \n\n
-- Ported from http://www.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/key.c.
fingerprint_visual = function( fingerprint, algorithm, bits )
  local i,j,field,characters,input,fieldsize_x,fieldsize_y,s
  fieldsize_x, fieldsize_y = 17, 9
  characters = {' ','.','o','+','=','*','B','O','X','@','%','&','#','/','^','S','E'}

  -- initialize drawing area
  field = {}
  for i=1,fieldsize_x do
    field[i]={}
    for j=1,fieldsize_y do field[i][j]=1 end
  end

  -- we start in the center and mark it
  x, y = math.ceil(fieldsize_x/2), math.ceil(fieldsize_y/2)
  field[x][y] = #characters - 1;

  -- iterate over fingerprint 
  for i=1,#fingerprint do
    input = fingerprint:byte(i)
    -- each byte conveys four 2-bit move commands 
    for j=1,4 do
      if bit.band( input, 1) == 1 then x = x + 1 else x = x - 1 end
      if bit.band( input, 2) == 2 then y = y + 1 else y = y - 1 end

      x = math.max(x,1); x = math.min(x,fieldsize_x)
      y = math.max(y,1); y = math.min(y,fieldsize_y)

      if field[x][y] < #characters - 2 then
        field[x][y] = field[x][y] + 1
      end
      input = bit.rshift( input, 2 )
    end
  end

  -- mark end point
  field[x][y] = #characters;

  -- build output
  s = ('\n+--[%4s %4d]----+\n'):format( algorithm, bits )
  for i=1,fieldsize_y do
    s = s .. '|'
    for j=1,fieldsize_x do s = s .. characters[ field[j][i] ] end
    s = s .. '|\n'
  end
  s = s .. '+-----------------+\n'
  return s
end

