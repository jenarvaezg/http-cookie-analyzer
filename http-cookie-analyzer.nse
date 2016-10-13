local httpspider = require "httpspider"
local shortport = require "shortport"
local tab = require "tab"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local http = require "http"
local string = require "string"
local os = require "os"

description = [[
	cosas
]]

author = "a y b"
license = "eh"
categories = {"discovery", "safe"}

portrule = shortport.http

local function analyzeCookie(cookie, url)
	local url = tostring(url)

	url = string.gsub(url, "https://", "")
	url = string.gsub(url, "http://", "")
	url = string.gsub(url, ":%d*", "")
	url = string.gsub(url, "www.", "")
	url = string.gsub(url, "?%c*", "")	


	local slash_pos = string.find(url, "/")
	if(not(slash_pos)) then
		url = url .. "/"
		slash_pos = string.len(url) - 1 
	end
	local domain = "." .. string.sub(url, 0 , slash_pos - 1 )
	local path = string.sub(url, slash_pos)

	if(cookie.path ~= path) then
		print("loose path: " .. cookie.path .. "  " .. path)
	end
	if(cookie.domain ~= domain) then
		print("loose domain" .. cookie.domain .. "  " .. domain)
	end

	print(os.date())
	print(cookie.expires)

end

action = function(host, port)
	local crawler = httpspider.Crawler:new(host, port, nil, {scriptname = SCRIPT_NAME})
	if(not(crawler)) then
		return
	end
	crawler:set_timeout(10000)
	
	local cookie_urls = tab.new(6)
	tab.addrow(cookie_urls, "url", "name", "value", "domain", "path", "expires")

	while(true) do
		local status, r = crawler:crawl()
		if(not(status)) then
			if(r.err) then
				return stdnse.format_output(true, ("ERROR: %s"):format(r.reason))
			else
				break
			end
		end
		local cookies = r.response.cookies
		if(#cookies > 0) then
			for _, cookie in ipairs(cookies) do
				analyzeCookie(cookie, r.url)
				tab.addrow(cookie_urls, r.url, cookie.name, cookie.value, cookie.domain, cookie.path, cookie.expires)
			end
		end
	end
	
	if(#cookie_urls > 1) then
		local result = {tab.dump(cookie_urls)}
		result.name = crawler:getLimitations()
		return stdnse.format_output(true, result)
	end

end
