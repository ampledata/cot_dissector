----------------------------------------
--
-- Copyright (c) 2018, Honu Ltd.
--
-- author: William Lupton <william@honu.co.uk>
--
-- This code is licensed under the MIT license.
--
-- Version: 1.0
--
------------------------------------------

-- prevent wireshark loading this file as a plugin
if not _G['protbuf_dissector'] then return end


local Settings = require "settings"
local dprint   = Settings.dprint
local dprint2  = Settings.dprint2
local dassert  = Settings.dassert
local derror   = Settings.derror
local dsummary = Settings.dsummary


-------------------------------------------------------------------------------
-- Application protocol registry and dispatcher. Handles dissection of
-- application protocol headers and protobuf payload re-assembly (where
-- needed).
--

local Dispatch = {}

local Handler = {}
local Handler_mt = { __index = Handler }

function Handler:reset()
    return self.payload:reset()
end

function Handler:set_field_name(field_name)
    return self.payload:set_field_name(field_name)
end

function Handler:set_field_value(number, field_value)
    return self.payload:set_field_value(number, field_value)
end

function Handler:dissect_app_packet(tvbuf, pktinfo, root)
    dassert(false, "Handler:dissect_app_packet() not overridden")
end

function Handler:check_sublayer_payload(tvbuf, pktinfo, root)
    dassert(false, "Handler:check_sublayer_payload() not overridden")
end

function Handler.new(payload, port_type, port)
    local new_class = {
        payload = payload,

        -- TCP=2?, UDP=3
        port_type = port_type,

        port = port,
    }
    setmetatable( new_class, Handler_mt )
    return new_class
end


local Dispatcher = {}
local Dispatcher_mt = { __index = Dispatcher }

function Dispatcher:register(handler)
    local name = handler.payload.name
    if self.registrations[name] then
        derror("Dispatch:register() " .. name .. " already registered")
    else
        self.registrations[name] = handler
    end
end

function Dispatcher:unregister(handler)
    local name = handler.payload.name
    if not self.registrations[name] then
        derror("Dispatch.unregister() " .. name .. " not registered")
    else
        self.registrations[name] = nil
    end
end

function Dispatcher:reset()
    if self.registrations then
        for _, handler in pairs(self.registrations) do
            handler:reset()
        end
    end
end

function Dispatcher:set_field_name(field_name)
    if self.registrations then
        for _, handler in pairs(self.registrations) do
            handler:set_field_name(field_name)
        end
    end
end

function Dispatcher:set_field_value(number, field_value)
    if self.registrations then
        for _, handler in pairs(self.registrations) do
            handler:set_field_value(number, field_value)
        end
    end
end

-- dissect the app packet and, if available, return its protobuf payload
-- (potentially collected from multiple packets)
function Dispatcher:dissect_app_packet(tvbuf, pktinfo, root)
    -- XXX need also to check the port type
    if self.registrations then
        for _, handler in pairs(self.registrations) do
            if (pktinfo.src_port == handler.port or
                pktinfo.dst_port == handler.port) then
                dsummary("Dispatcher:dissect_app_packet()", "handler", handler)
                tvbuf = handler:dissect_app_packet(tvbuf, pktinfo, root)
                if tvbuf then
                    break
                end
            end
        end
    end
    return tvbuf
end

-- XXX this is really a different beast; we should split Dispatchers into
--     two categories: ApplicationDispatcher and SublayerDispatcher (hmm...
--     "sub-layer" is a bad name, because it's really an _upper_ layer!
function Dispatcher:check_sublayer_payload(tvbuf, pktinfo, root)
    if self.registrations then
        for _, handler in pairs(self.registrations) do
            handler:check_sublayer_payload(tvbuf, pktinfo, root)
        end
    end
end

-- if this handles the buffer, it returns nothing; otherwise it returns
-- the unhandled buffer to be handled by the caller
function Dispatcher:dispatch(tvbuf, pktinfo, root)
    local number = pktinfo.number
    local visited = pktinfo.visited
    local offset = tvbuf:offset()

    dprint("Dispatcher:dispatch()", "number", number, "visited", visited,
           "offset", offset)

    if offset == 0 then
        -- a zero offset means the packet contains only a protobuf message
        -- (no lower-layer headers), so it's handed back to the caller
        -- XXX is there a more direct way to determine this?
        return tvbuf
    end

    -- otherwise, pass it to the application-layer dissectors (they are
    -- tried in turn until one of them chooses to handle it)
    local new_tvbuf = self:dissect_app_packet(tvbuf, pktinfo, root)
    if not new_tvbuf then
        return
    end

    -- the returned buffer might be either
    -- 1. based on a range from this packet (in which case it could be
    --    returned to the caller)
    -- 2. the result of concatenating ranges from multiple packets (in
    --    which case it must be handled here)
    -- XXX temporarily assume the first
    -- XXX hmm... this seems to work in the other case too!
    if true then
        return new_tvbuf
    else
        local usp_record_dissector = Dissector.get("usp_record.record")
        usp_record_dissector:call(new_tvbuf, pktinfo, root)
    end
    return
end


function Dispatcher.new()
    local new_class = {
        registrations = {}
    }
    setmetatable( new_class, Dispatcher_mt )
    return new_class
end


Dispatch.Handler = Handler
Dispatch.Dispatcher = Dispatcher
Dispatch.dispatcher = Dispatcher.new()

return Dispatch
