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

local AstFactory      = require "ast.factory"
local StatementBase   = require "ast.statement_base"
local Identifier      = require "ast.identifier"
local OptionStatement = require "ast.option"


----------------------------------------
-- MapStatement class, for "map" statements
--
local MapStatement = {}
local MapStatement_mt = { __index = MapStatement }
setmetatable( MapStatement, { __index = StatementBase } ) -- make it inherit from StatementBase
AstFactory:registerClass("MAP", "MapStatement", MapStatement, true)


function MapStatement.preParse(st)
    dassert(AstFactory.verifyTokenTTypes("Map", st, "MAP", "ANGLE_BLOCK", "IDENTIFIER",
                                         "EQUAL", "NUMBER"))
    -- return Identifier.new(st, 2)
end


function MapStatement:postParse(st, id, namespace)
    -- local ns = namespace:addDeclaration(id, self)

    local value  = {}
    local tokens = st[2].value
    dassert(#tokens == 3 and tokens[1]:isNativeType() and tokens[2].ttype == "COMMA" and
                tokens[3]:canBeIdentifier(), "invalid map <key_type, value_type> block")
    dprint("map")
    dprint("- key_type", tokens[1])
    dprint("- value_type", tokens[3])
    dprint("- map_field", st[3])
    dprint("- N", st[5])

    -- map<key_type, value_type> map_field = N;
    --
    -- becomes:
    --
    -- message MapFieldEntry {
    --   key_type key = 1;
    --   value_type value = 2;
    -- }
    -- repeated MapFieldEntry map_field = N;

    -- return ns, value
end


function MapStatement.new(namespace, st)
    local id = MapStatement.preParse(st)
    local new_class = StatementBase.new("MAP", id)
    setmetatable( new_class, MapStatement_mt )
    -- call postParse on the new instance
    local ns, value = new_class:postParse(st, id, namespace)
    -- new_class:setNamespace(ns)
    new_class:setValue(value)
    return new_class
end


function MapStatement:analyze()
end
