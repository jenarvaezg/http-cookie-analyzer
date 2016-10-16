local httpspider = require "httpspider"
local shortport = require "shortport"
local tab = require "tab"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local http = require "http"
local string = require "string"
local os = require "os"
local date = require "date"

description = [[
        Spiders a web site to find missconfigured cookies. Based on the OWASP documentation.
        https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OTG-SESS-002)
]]

author = "José Enrique Narvaez y David Catalán Alegre"
license = "eh"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({80, 443}, {"http","https"})

local function stripURL(url)

        url = string.gsub(url, "https://", "")
        url = string.gsub(url, "http://", "")
        url = string.gsub(url, ":%d*", "")
        url = string.gsub(url, "www.", "")
        url = string.gsub(url, "?*", "")


        local slash_pos = string.find(url, "/")
        if(not(slash_pos)) then
                url = url .. "/"
                slash_pos = string.len(url) - 1
        end
        local domain = "." .. string.sub(url, 0 , slash_pos - 1 )
        local path = string.sub(url, slash_pos)
	

	return domain, path
end

local function analyzeCookie(cookie, url, set_cookie, port)

        local domain, path = stripURL(tostring(url))	
        local info = "Cookie: " .. cookie.name .. " at " .. tostring(url) .. "\n"
        
        if(cookie.path ~= path) then
		info = info .. "\tLoose path found: " .. cookie.path .. " at " .. path .. "\n"
                -- print("loose path: " .. cookie.path .. "  " .. path)
	end
	
        if(cookie.domain ~= domain) then
		if cookie.domain == nil then
                        cookie.domain = "EMPTY"

                        if string.find(cookie.name, "[sS][eE][sS][sS][iI][oO][nN]") then
                                info = info .. "\tNOTE: This might be a well configured session cookie. Check OWASP Session Management Cheat Sheet.\n"
                                --print("This might be a well configured session cookie. Check OWASP Session Management Cheat Sheet")
                        end
                end

                info = info .. "\tLoose domain found: " .. cookie.domain .. " at " .. domain .. "\n"
                --print("loose domain: " .. cookie.domain .. "  " .. domain)
	end
	

        if cookie.expires ~= nil then
                 
	        local d1 = date('Sat, 29 Oct 1994 19:43:31 GMT')                                                                                               
	        local now = date(true)
	        local cookie_expiry = date(tostring(cookie.expires))
	        if(cookie_expiry < date("01 Jan 2000")) then
		        cookie_expiry = cookie_expiry:addyears(100) 
	        end
        
	        local days = date.diff(cookie_expiry, now):spandays()
	        if(days >= 365) then
		        info = info .. "\tLong-term persistent cookie: " .. cookie_expiry .. "\n"
                        --print("More than a year expiration: " .. cookie_expiry)
        	end
        end

        if port == 80 or not string.find(set_cookie, "secure") then
                info = info .. "\tThis cookie can be sent through unencrypted channels!\n"
                --print("This cookie can be sent through unencrypted channels!")
        end

        if not string.find(set_cookie, "httponly") then
               info = info .. "\tCookie exposed to XSS attacks(httpOnly flag not set).\n"
               --print("Cookie exposed to XSS attacks!") 
        end

        info = info .. "\n"
        return info
end

action = function(host, port)
	local crawler = httpspider.Crawler:new(host, port, nil, {scriptname = SCRIPT_NAME})
	if(not(crawler)) then
		return
	end
	crawler:set_timeout(10000)
	
	local cookie_urls = tab.new(6)
	tab.addrow(cookie_urls, "url", "name", "value", "domain", "path", "expires")

        local cookie_info = ""
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
                                local set_cookie = r.response.header["set-cookie"]
				cookie_info = cookie_info ..  analyzeCookie(cookie, r.url, set_cookie, port.number) 
                                tab.addrow(cookie_urls, r.url, cookie.name, cookie.value, cookie.domain, cookie.path, cookie.expires)
			end
		end
	end
	
	if(#cookie_urls > 1) then
		local result = {tab.dump(cookie_urls)}
		result.name = crawler:getLimitations()
	        return stdnse.format_output(true, result) .. cookie_info
	end

end
