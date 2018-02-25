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
-- Payload class, for extracting higher-layer payloads from a set of packets
-- in a conversation.
--
-- This can be used both for:
-- 1. protobuf payload re-assembly, e.g. where a protobuf message is split
--    across multiple HTTP or CoAP packets
-- 2. higher-level (within protobuf) payload assembly, e.g. where a protobuf
--    message carries a higher-level (opaque to it) protobuf message that may
--    be split across multiple lower-level messages
--
-- In both cases, explicit knowledge of the lower-level ("carrier") protocol
-- is needed, but this class works in terms of generic fields (with names
-- based on CoAP):
-- 1. session - session ID that identifies a set of related packets
-- 2. block - block number (1-based) that counts the packets within a session
-- 3. more - boolean that indicates whether more packets are needed before the
--    higher-layer payload can be extracted
-- 4. payload - each packet's payload (to be concatenated and passed on)

-- XXX need to rename this class! its name doesn't correspond to its usage
local Payload = {}
local Payload_mt = { __index = Payload }

-- this also defines the internal field names
local field_types = {session='string', block='number', more='boolean',
                     payload='tvrange'}

function Payload:set_field_name(ename, is_internal)
    local iname = is_internal and ename or self.field_name_map[ename]
    if field_types[iname] then
        self.field_name = iname
    else
        self.field_name = ""
    end
end

-- XXX need something better than number here; conversation _and_ number?
function Payload:set_field_value(number, evalue, is_internal, quiet)
    if self.field_name ~= "" then
        local pft = field_types[self.field_name]
        -- XXX why doesn't this work?
        -- local ivalue = self.field_value_mapper[self.field_name] and
        --     self.field_value_mapper[self.field_name](evalue) or evalue
        local ivalue = evalue
        if not is_internal and self.field_value_mapper[self.field_name] then
            ivalue = self.field_value_mapper[self.field_name](evalue)
        end
        if pft == 'boolean' then
            ivalue = tostring(ivalue) == "true" or tostring(ivalue) == "1"
        elseif pft == 'number' then
            ivalue = tonumber(tostring(ivalue))
        elseif pft == 'string' then
            ivalue = tostring(ivalue)
        elseif pft == 'tvrange' then
            ivalue = tostring(ivalue:bytes())
        else
            dassert(false, "Invalid payload field type " .. pft)
        end

        if not self.field_info[number] then
            self.field_info[number] = {}
        end
        if pft ~= 'tvrange' then
            self.field_info[number][self.field_name] = ivalue
        else
            if not self.field_info[number][self.field_name] then
                self.field_info[number][self.field_name] = {}
            end
            table.insert(self.field_info[number][self.field_name], ivalue)
        end
        self.last_number = number

        if not quiet then
            dsummary("Payload:set_field_value() (" .. number .. " " ..
                     self.field_name .. " " .. tostring(ivalue) .. ")",
                     "self", self)
        end
    end
end

-- the Payload:set_field_name() and Payload:set_field_value() interface is to
-- make it easy to capture information as protobuf payloads are being parsed;
-- this helper function is more convenient for the cases where all the fields
-- are already available
function Payload:set_field_values(number, info, is_internal)
    local saved_field_name = self.field_name
    for ename, evalue in pairs(info) do
        self:set_field_name(ename, is_internal)
        self:set_field_value(number, evalue, is_internal, true)
    end
    self.field_name = saved_field_name
    dsummary("Payload:set_field_values()", "self", self)
end

function Payload:more()
    dassert(self.last_number, "Payload:more() can't be called before " ..
                "Payload:set_field_value()")
    local more = self.field_name == "payload" and
        self.field_info[self.last_number].more
    return more
end

-- XXX need to ensure that payload entirely packet retains the original buffer
-- XXX not checking for missing or duplicate records
function Payload:get_payload_hex_string()
    dassert(self.last_number, "Payload:get_payload_hex_string() can't be " ..
                "called before Payload:set_field_value()")
    local session = self.field_info[self.last_number].session
    local payload
    if session == nil then
        payload = self.field_info[self.last_number].payload[1]
    else
        local chunks = {}
        for _, info in pairs(self.field_info) do
            if info.session == session then
                -- XXX this is wrong if there are multiple "bytes" entries
                --     (luckily only my test data currently does this!)
                chunks[info.block] = info.payload[1]
            end
        end
        dsummary("Payload:get_payload_hex_string()", "chunks", chunks)
        payload = table.concat(chunks)
    end
    dsummary("Payload:get_payload_hex_string()", "payload", payload)
    return payload
end

function Payload:reset()
    -- this doesn't reset the field_name_map and field_value_mapper
    -- (because they are set only in the constructor)
    self.field_name = ""
    self.field_info = {}
    self.last_number = nil
end

function Payload:init(field_name_mapping_info)
    self.field_name_map = {}
    for iname, mapping_info in pairs(field_name_mapping_info) do
        local ename = mapping_info[1]
        dassert(field_types[iname], "Payload:init() invalid internal " ..
                    "field name " .. iname)
        self.field_name_map[ename] = iname
        self.field_value_mapper[iname] = mapping_info[2]
    end
end

function Payload.new(name, field_name_mapping_info)
    dsummary("Payload.new()", "args",
             {name=name, field_name_mapping_info=field_name_mapping_info})
    local new_class = { -- the new instance
        -- payload name
        name = name,

        -- map from external to internal (generic) field names
        -- (it's populated by the init function)
        field_name_map = {},

        -- map from external to internal field value
        -- (it's populated by the init function)
        field_value_mapper = {},

        -- current field name
        field_name = "",

        -- map of packet number -> internal field name -> internal field value
        field_info = {},

        -- last packet number for which field info was saved
        last_number = nil,
    }
    setmetatable( new_class, Payload_mt )

    new_class:reset()
    new_class:init(field_name_mapping_info)
    dsummary("Payload:new() (after reset+init)", "new_class", new_class)
    return new_class
end

return Payload
