-- Prosody IM
-- Copyright (C) 2017 Atlassian
--

local jid = require "util.jid";
local it = require "util.iterators";
local json = require "util.json";
local iterators = require "util.iterators";
local array = require"util.array";
local wrap_async_run = module:require "util".wrap_async_run;

local tostring = tostring;
local neturl = require "net.url";
local parse = neturl.parseQuery;

-- option to enable/disable room API token verifications
local enableTokenVerification
    = module:get_option_boolean("enable_roomsize_token_verification", false);

local token_util = module:require "token/util".new(module);
local get_room_from_jid = module:require "util".get_room_from_jid;

-- no token configuration but required
if token_util == nil and enableTokenVerification then
    log("error", "no token configuration but it is required");
    return;
end

-- required parameter for custom muc component prefix,
-- defaults to "conference"
local muc_domain_prefix
    = module:get_option_string("muc_mapper_domain_prefix", "conference");

--- Verifies room name, domain name with the values in the token
-- @param token the token we received
-- @param room_address the full room address jid
-- @return true if values are ok or false otherwise
function verify_token(token, room_address)
    if not enableTokenVerification then
        return true;
    end

    -- if enableTokenVerification is enabled and we do not have token
    -- stop here, cause the main virtual host can have guest access enabled
    -- (allowEmptyToken = true) and we will allow access to rooms info without
    -- a token
    if token == nil then
        log("warn", "no token provided");
        return false;
    end

    local session = {};
    session.auth_token = token;
    local verified, reason = token_util:process_and_verify_token(session);
    if not verified then
        log("warn", "not a valid token %s", tostring(reason));
        return false;
    end

    if not token_util:verify_room(session, room_address) then
        log("warn", "Token %s not allowed to join: %s",
            tostring(token), tostring(room_address));
        return false;
    end

    return true;
end

--- Handles request for retrieving the room size
-- @param event the http event, holds the request query
-- @return GET response, containing a json with participants count,
--         tha value is without counting the focus.
function handle_get_room_size(event)
    if (not event.request.url.query) then
        return 400;
    end

	local params = parse(event.request.url.query);
	local room_name = params["room"];
	local domain_name = params["domain"];
    local subdomain = params["subdomain"];

    local room_address
        = jid.join(room_name, muc_domain_prefix.."."..domain_name);

    if subdomain and subdomain ~= "" then
        room_address = "["..subdomain.."]"..room_address;
    end

    if not verify_token(params["token"], room_address) then
        return 403;
    end

	local room = get_room_from_jid(room_address);
	local participant_count = 0;

	log("debug", "Querying room %s", tostring(room_address));

	if room then
		local occupants = room._occupants;
		if occupants then
			participant_count = iterators.count(room:each_occupant());
		end
		log("debug",
            "there are %s occupants in room", tostring(participant_count));
	else
		log("debug", "no such room exists");
		return 404;
	end

	if participant_count > 1 then
		participant_count = participant_count - 1;
	end

	return [[{"participants":]]..participant_count..[[}]];
end

--- Handles request for retrieving the room participants details
-- @param event the http event, holds the request query
-- @return GET response, containing a json with participants details
function handle_get_room (event)
    if (not event.request.url.query) then
        return 400;
    end

	local params = parse(event.request.url.query);
	local room_name = params["room"];
	local domain_name = params["domain"];
    local subdomain = params["subdomain"];
    local room_address
        = jid.join(room_name, muc_domain_prefix.."."..domain_name);

    if subdomain ~= "" then
        room_address = "["..subdomain.."]"..room_address;
    end

    if not verify_token(params["token"], room_address) then
        return 403;
    end

	local room = get_room_from_jid(room_address);
	local participant_count = 0;
	local occupants_json = array();

	log("debug", "Querying room %s", tostring(room_address));

	if room then
		local occupants = room._occupants;
		if occupants then
			participant_count = iterators.count(room:each_occupant());
			for _, occupant in room:each_occupant() do
			    -- filter focus as we keep it as hidden participant
			    if string.sub(occupant.nick,-string.len("/focus"))~="/focus" then
				    for _, pr in occupant:each_session() do
					local nick = pr:get_child_text("nick", "http://jabber.org/protocol/nick") or "";
					local email = pr:get_child_text("email") or "";
					occupants_json:push({
					    jid = tostring(occupant.nick),
					    email = tostring(email),
					    display_name = tostring(nick)});
				    end
			    end
			end
		end
		log("debug",
            "there are %s occupants in room", tostring(participant_count));
	else
		log("debug", "no such room exists");
		return 404;
	end

	if participant_count > 1 then
		participant_count = participant_count - 1;
	end

	return json.encode(occupants_json);
end;

function tablelength(T)
        local hash = {}
        local res = {}

        for _,v in ipairs(T) do
           if (not hash[v]) then
               res[#res+1] = v
               hash[v] = true
           end
        end

        local count = 0
        for _ in pairs(res) do count = count + 1 end
        return count
end

function getNbConfPart() 
    local tab={};

    --conferences count (without eliminating duplicates )
    for key, value in pairs(prosody.full_sessions) do
            if tostring(value["username"]:lower()) ~= "focus" then
                    table.insert(tab,tostring(value["jitsi_meet_room"]:lower()));
            end
    end

    local nbPart = 0
    if it.count(it.keys(prosody.full_sessions))-1 >= 0 --participants count
            then nbPart= it.count(it.keys(prosody.full_sessions))-1
    end

    local nbConf = tablelength(tab) --conferences count
    if nbPart == 0
            then nbConf=0
    end

     --create result as json
    local result_json=array();
    result_json:push({
                    part= nbPart,
                    conf=tablelength(tab) -- eliminates count number of rooms
            });

    -- create json response 
    return json.encode(result_json);
end

function has_value(tab, val)
   for _, value in ipairs(tab) do
       if value == val then
           return true
       end
   end
   return false
end

function get_info_rooms()
   local innerValues = {};
   local keyRoom = "jitsi_bosh_query_room";
   for _, value in pairs(prosody.full_sessions) do
       if tostring(value["username"]:lower()) ~= "focus" then
           for innerKey, innerValue in pairs(value) do
               if innerKey == keyRoom and not has_value(innerValues, innerValue) then
                   table.insert(innerValues, innerValue)
               end
           end
       end
   end
return json.encode(innerValues);
end

function module.load()
    module:depends("http");
	module:provides("http", {
		default_path = "/";
		route = {
			["GET room-size"] = function (event) return wrap_async_run(event,handle_get_room_size) end;
			["GET sessions"] = function () return tostring(it.count(it.keys(prosody.full_sessions))); end;
			["GET room"] = function (event) return wrap_async_run(event,handle_get_room) end;
			["GET nbConfPart"] = function (event) return wrap_async_run(event,getNbConfPart) end;
      ["GET get-info-rooms"] = function (event) return wrap_async_run(event,get_info_rooms) end;
		};
	});
end
