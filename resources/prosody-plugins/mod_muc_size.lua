-- Prosody IM
-- Copyright (C) 2017 Atlassian
--
local jid = require "util.jid";
local it = require "util.iterators";
local json = require "util.json";
local iterators = require "util.iterators";
local array = require"util.array";

local have_async = pcall(require, "util.async");
if not have_async then
    module:log("error", "requires a version of Prosody with util.async");
    return;
end

local async_handler_wrapper = module:require "util".async_handler_wrapper;

local tostring = tostring;
local neturl = require "net.url";
local parse = neturl.parseQuery;

local basexx = require "basexx";
-- option to enable/disable room API token verifications
local enableTokenVerification = true

local token_util = module:require "token/util".new(module);


-- no token configuration but required
if token_util == nil and enableTokenVerification then
    log("error", "no token configuration but it is required");
    return;
end

-- required parameter for custom muc component prefix,
-- defaults to "conference"
local muc_domain_prefix
    = module:get_option_string("muc_mapper_domain_prefix", "conference");

local muc_component_host = module:get_option_string("muc_component");

--- Verifies if the user id admin with the values in the token
function checkAffiliation(token)
    if token then
            -- Extract token body and decode it
            local dotFirst = token:find("%.");
            if dotFirst then
                    local dotSecond = token:sub(dotFirst + 1):find("%.");
                    if dotSecond then
                            local bodyB64 = token:sub(dotFirst + 1, dotFirst + dotSecond - 1);
                            local body = json.decode(basexx.from_url64(bodyB64));
                            -- If user is a moderator, set their affiliation to be an owner
                            if body["admin"] == true then
                                    return true
                            else
                                    return false
                            end;
                    end;
            end;
    end;
end;

--- Verifies domain name with the values in the token
-- @param token the token we received
-- @param room_address the full room address jid
-- @return true if values are ok or false otherwise
function verify_token(token)
    if not enableTokenVerification then
        return true;
    end

    -- COMMENT BELOW THREE LINES IF YOU DON'T WANT ADMIN CHECK
    if not checkAffiliation(token) then
        return false;
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
    -- UNCOMMENT BELOW FOUR LINES IF YOU WANT ROOM CHECK IN TOKEN

    -- if not token_util:verify_room(session, room_address) then
    --     log("warn", "Token %s not allowed to join: %s",
    --         tostring(token), tostring(room_address));
    --     return false;
    -- end

    return true;
end

--- Handles request for retrieving the room size
-- @param event the http event, holds the request query
-- @return GET response, containing a json with participants count,
--         tha value is without counting the focus.
function handle_get_room_size(event)
    if (not event.request.url.query) then
        return { status_code = 400; };
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

    if not verify_token(params["token"]) then
        return { status_code = 403; };
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
		return { status_code = 200; body = [[{"participants":]].."0"..[[}]] };
	end

	if participant_count > 1 then
		participant_count = participant_count - 1;
	end

	return { status_code = 200; body = [[{"participants":]]..participant_count..[[}]] };
end

--- Handles request for retrieving the room participants details
-- @param event the http event, holds the request query
-- @return GET response, containing a json with participants details
function handle_get_room (event)
    if (not event.request.url.query) then
        return { status_code = 400; };
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

    if not verify_token(params["token"]) then
        return { status_code = 403; };
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
		return { status_code = 200; body = json.encode(occupants_json); };
	end

	if participant_count > 1 then
		participant_count = participant_count - 1;
	end

	return { status_code = 200; body = json.encode(occupants_json); };
end;

function handle_list_room(event)
    if (not event.request.url.query) then
        return { status_code = 400; };
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

    if not verify_token(params["token"]) then
        return { status_code = 403; };
    end

    local _, host = jid.split(room_address);
    local component = hosts[host];
    local room_names = array()
    if component then
        local muc = component.modules.muc
        for room in muc.all_rooms() do
            table.insert(room_names, tostring(room:get_name()))
        end 
    end
    return { status_code = 200; body = json.encode(room_names); };
end;


function get_room_from_jid(room_jid)
    local _, host = jid.split(room_jid);
    local component = hosts[host];
    if component then
        local muc = component.modules.muc
        if muc and rawget(muc,"rooms") then
            -- We're running 0.9.x or 0.10 (old MUC API)
            return muc.rooms[room_jid];
        elseif muc and rawget(muc,"get_room_from_jid") then
            -- We're running >0.10 (new MUC API)
            return muc.get_room_from_jid(room_jid);
        else
           
            return
        end
    end
end

function get_sessions(event)
    if (not event.request.url.query) then
        return { status_code = 400; };
    end

    local params = parse(event.request.url.query);
    
    if not verify_token(params["token"]) then
        return { status_code = 403; };
    else
        local session_count = it.count(it.keys(prosody.full_sessions)) - 2;
        if (session_count > 0) then
            return { status_code = 200; body = tostring(session_count) };
        else
            return { status_code = 200; body = tostring(0) };
        end
    end
end

function module.load()
    module:depends("http");
	module:provides("http", {
		default_path = "/";
		route = {
			["GET room-size"] = function (event) return async_handler_wrapper(event,handle_get_room_size) end;
			["GET sessions"] = function (event) return async_handler_wrapper(event,get_sessions) end;
            ["GET room"] = function (event) return async_handler_wrapper(event,handle_get_room) end;
            ["GET room-list"] = function (event) return async_handler_wrapper(event,handle_list_room) end;
		};
	});
end
