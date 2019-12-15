-- fileshark_pcap.lua
--------------------------------------------------------------------------------
--[[
    This is a Wireshark Lua-based pcap *format* dissector (i.e., FileShark).

    Author: Hadriel Kaplan
    Copyright (c) 2014, Hadriel Kaplan

    License: Public Domain; or MIT license if you prefer, copyright 2014 Hadriel Kaplan.

    Version: 1.0

    This "capture file" reader reads pcap files - the old style ones - as a FileShark
    implementation. What does that mean? It means it reads a pcap file and displays
    the contents of the file format itself, showing the file header, record
    headers, etc., and their fields. To do this it creates a "pcapfile" protocol
    dissector, with associated protocol fields of what pcap file formats have.

    There are several preferences that can be set in Wireshark, under the "PcapFile"
    protocol. (Edit->Preferences->Protocols->PcapFile)

    This script file is written with a LOT of comments... maybe too many comments.
    The reason for this is so it can be used as a form of tutorial. I suggest you
    view it using a editor that does syntax highlighting for Lua, so you can distinguish
    comments separately visually. (SublimeText is a good one, imho)

    Requirements:
    1. This script requires Wireshark v1.11.3 or newer.

    2. For this reader to accept a pcap file, it MUST be able to (1) read a full file
    header (i.e., the file has to be at least 24 bytes big), and (2) read a magic value
    we understand (i.e., one of the supported ones). Even though this is fileshark,
    it only makes sense to have some minimum requirement to read a file.

    If the above conditions are met, this reader accepts the file and does its
    best to decode the pcap file.

    Pcap Formats Not Supported:
    This reader+dissector handles multiple flavors of Pcap files, EXCEPT not
    the following: AIX's non-standard tcpdump, DG/UX's tcpdump version 543,
    Nokia's non-standard format possibly used by some firewall product, and
    Alexey Kuznetsov's modified format from patches ss990417 and ss990915.

    Pcap Formats Supported:
    It does though handle Alexey Kuznetsov's last patch ss991029, and Ulf
    Lamping's nanosecond resolution pcap format. I think it should handle
    Pcap formats prior to version 2.3, but I don't have any samples to try.
    The current Pcap format is version 2.4, and has been for a long time.

    Details: 
    So how does this work? Basically this script is two scripts in one: it's
    a script defining a new protocol/dissector for a "pcapfile" protocol, and
    it's also a script for a wireshark file reader (to read pcap files).

    The file reader portion reads in a pcap file, but unlike the built-in pcap
    file reader in Wireshark, this script tries to accept malformed pcap files,
    assuming it meets the "Requirements" section above. And unlike the built-in
    one, this script reads the pcap headers to learn what it needs to learn, but
    it also feeds in the whole header as part of the frame data to be dissected,
    as wtap encap type USER13. The dissector portion of this script is registered
    to dissect USER13 encap types, and decodes the pcap headers as the "protocol"
    PDU. The encap type (USER13) can be changed through preference settings.

    Doing this is a little confusing to read, because we need to create both a
    file reader to read in the pcap file, as well as a protocol dissector to
    show the contents thereof. It's tricky because Wireshark expects a file
    reader to provide meta-information about records, including link types and
    such, and for the file to be formatted correctly. In our case there is no
    actual network "link-type" - it's a pcap file format "link-type". Unfortunately,
    new encapsulation types can't be created/added by Lua (yet). So we'll have to
    use an existing one. This script uses USER13 by default, but it can be changed
    by a preference setting in case it conflicts with one you use already. We also
    need to handle file reading errors carefully, in the sense that we want to
    show as much as possible even for malformed files. The odd thing is we need
    to parse pcap file+record headers for both reading of the file, as well as
    for displaying as a dissected protocol content - meaning we need to do it
    twice but in different ways. (e.g., there is no "TVB" buffer or tree or pinfo
    while reading a file - only during dissection)
--]]
--------------------------------------------------------------------------------

-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- note this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1


----------------------------------------
-- sanity checking stuff
local wireshark_name = "Wireshark"
if not GUI_ENABLED then
    wireshark_name = "Tshark"
end

-- verify Wireshark is new enough
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your " .. wireshark_name .. " version (" .. get_version() .. ") is too old for this script!\n" ..
                "This script needs " .. wireshark_name .. "version 1.11.3 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, wireshark_name .. " does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

-- we need the big table of Pcap linktypes --> wtap numbers
local LINKTYPE = require "linktype"

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- early definitions
-- throughout most of this file I try to pre-declare things to help ease
-- reading it and following the logic flow, but some things just have to be done
-- before others, so this sections has such things that cannot be avoided
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

-- first some variable declarations for functions we'll define later
local dissect_pcap_file_hdr, dissect_pcap_record, dissect_pcap_modified_record

----------------------------------------
-- throughout this script, we need to keep state/settings based on the
-- pcap file header info we dissect or read. This table represents the default
-- values of such. It doesn't get used directly - instead, each file we open for
-- reading will create a copy of this table, and then change its copy based on
-- the pcap magic and other fields it finds in the file header. This is necessary
-- for a couple reasons: (1) files are closed/opened so that state needs to be
-- reset at certain points, and (2) there can actually be multiple pcap files
-- being read from at the same time and we don't want to clobber the settings.
-- This second point happens because a file can be reloaded by wireshark, and
-- during reload the file is opened and checked for validity before the previous
-- file is closed. So we need to have two copies simply due to that. So each
-- time a file is opened for reading and we read a new file header, we create
-- a new copy of this table. And whenever the dissector function reads a file
-- header, it creates its own copy too, and replaces the previous one. Luckily
-- the dissector function isn't called for two different files at the same
-- time or we'd have a problem, because dissectors aren't given information
-- about which file they're dissecting from so we wouldn't be able to distinguish
-- the different files.
-- Note that I could have used two different "default" tables, one for file
-- reading functions and one for dissectors, because some of the fields here
-- are only used by one or the other but not both. But since some of the fields
-- are used by both, it's simpler to have one table.
local default_settings =
{
    debug_level     = DEBUG,
    name            = "unknown",
    corrected_magic = 0xa1b2c3d4,
    version_major   = 0,
    version_minor   = 0,
    timezone        = 0,
    sigfigs         = 0,
    read_snaplen    = 0, -- the snaplen we read from file
    snaplen         = 0, -- the snaplen we use (limited by WTAP_MAX_PACKET_SIZE)
    encap_type      = wtap.USER13, -- type reported to wireshark by read()/seek_read()
    linktype        = -1, -- the raw linktype number in the file header
    wtap_type       = wtap_encaps.UNKNOWN, -- the mapped internal wtap number based on linktype
    endianness      = ENC_BIG_ENDIAN,
    time_precision  = wtap_filetypes.TSPREC_USEC,
    time_secs       = 0, -- file creation time (will be set to first record's time later)
    time_nsecs      = 0, -- file creation time (will be set to first record's time later)
    rec_hdr_len     = 16,            -- default size of record header
    rec_hdr_patt    = "I4 I4 I4 I4", -- pattern for Struct to use
    num_rec_fields  = 4,             -- number of vars in pattern
    subdissect      = false, -- whether to call sub-dissector or not

    -- The following is the 'tree:add()' and 'tvb:uint()'' functions we're going to use.
    -- The reason we have a new variable for it instead of using tree:add() directly
    -- is that we change whether it points to 'TreeItem.add' or 'TreeItem.add_le'
    -- depending on endianness. Neat trick huh?
    -- The changing is done by create_magic_settings()
    -- same goes for tvbrange:uint()
    add             = TreeItem.add,
    uint            = TvbRange.uint,

    -- the following is the dissector function called for the record header
    -- we do it this way so we can change it for modified pcap format
    dissector       = function(...)
                        return dissect_pcap_record(...)
                      end
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

-- the function which makes a copy of the default settings per file/dissector
local function new_settings()
    dprint2("creating new file or dissector settings")
    local settings = {}
    for k,v in pairs(default_settings) do
        settings[k] = v
    end
    return settings
end

-- the following will be a function that creates the file/dissector-specific
-- settings based on the above default_settings table and the magic value
-- we declare it here, but define it at the bottom of this script file
local create_magic_settings

----------------------------------------
-- different pcap file types have different magic values
-- we need to know various things about them for various functions
-- in this script, so this table holds all the info
--
-- See default_settings table above for the defaults used if this table
-- doesn't override them.
--
-- Arguably, these magic types represent different "Protocols" to dissect later,
-- but this script treats them all as "pcapfile" protocol.
--
-- From this table, we'll auto-create a value-string table for file header magic field
local magic_spells =
{
    normal =
    {
        magic = 0xa1b2c3d4,
        name  = "Normal (Big-endian)",
    },
    swapped =
    {
        magic = 0xd4c3b2a1,
        name  = "Swapped Normal (Little-endian)",
        endianness = ENC_LITTLE_ENDIAN,
    },
    modified =
    {
        -- this is for a ss991029 patched format only
        magic = 0xa1b2cd34,
        name  = "Modified",
        rec_hdr_len    = 24,
        rec_hdr_patt   = "I4I4I4I4 I4 I2 I1 I1",
        num_rec_fields = 8,
        dissector = function(...)
                      return dissect_pcap_modified_record(...)
                    end
    },
    swapped_modified =
    {
        -- this is for a ss991029 patched format only
        magic = 0x34cdb2a1,
        name  = "Swapped Modified",
        rec_hdr_len    = 24,
        rec_hdr_patt   = "I4I4I4I4 I4 I2 I1 I1",
        num_rec_fields = 8,
        endianness = ENC_LITTLE_ENDIAN,
        dissector = function(...)
                      return dissect_pcap_modified_record(...)
                    end
    },
    nsecs =
    {
        magic = 0xa1b23c4d,
        name  = "Nanosecond",
        time_precision = wtap_filetypes.TSPREC_NSEC,
    },
    swapped_nsecs =
    {
        magic = 0x4d3cb2a1,
        name  = "Swapped Nanosecond",
        endianness      = ENC_LITTLE_ENDIAN,
        time_precision = wtap_filetypes.TSPREC_NSEC,
    },
}

-- create the value-string table from above magic_spells table
local magic_valstr = {}
for k,t in pairs(magic_spells) do
    magic_valstr[t.magic] = k
end

-- create a magic-to-spell entry table from above magic_spells table
-- so we can find them faster during file read operations
-- we could just add them right back into spells table, but this is cleaner
local magic_values = {}
for k,t in pairs(magic_spells) do
    magic_values[t.magic] = t
end


----------------------------------------
-- a value-string for time precision values
local precision_valstr = {
    [ wtap_filetypes.TSPREC_SEC ]  = "Seconds",      -- we give up
    [ wtap_filetypes.TSPREC_DSEC ] = "Deciseconds",  -- oh, so popular!
    [ wtap_filetypes.TSPREC_CSEC ] = "Centiseconds", -- also popular...not
    [ wtap_filetypes.TSPREC_MSEC ] = "Milliseconds", -- the 1970's called
    [ wtap_filetypes.TSPREC_USEC ] = "Microseconds", -- old and busted
    [ wtap_filetypes.TSPREC_NSEC ] = "Nanoseconds",  -- new hotness
}


--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- protocol creation
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

----------------------------------------
-- creates a Proto object, but doesn't register it yet
-- but there is already a "pcap" protocol/dissector, for: UTRAN Iupc interface Positioning
-- Calculation Application Part (PCAP). It is unfortunate that "pcap" was the name it was given
-- in wireshark, since it so clearly conflicts with the name of the file format wireshark
-- uses. Obviously it came before anyone thought of having a pcap dissector, but still...
-- the name confusion is so obvious, I'm tempted to go in and change the C-code. Ugh.
-- All right fine, so we'll use "pcapfile" instead. Grumble, grumble.
local proto_pcap = Proto("PcapFile", "Pcap File Format")


--------------------------------------------------------------------------------
-- create our ProtoFields
-- to be clever, we're going to put these in a Lua table instead of having them
-- be separate variables
--------------------------------------------------------------------------------

----------------------------------------
-- a table of all of our Protocol's fields
local pcap_fields =
{
    -- these are common fields for both file and record headers/entries
    common =
    {
        -- we have "File Header" and "Record Header" entry types, so create a ProtoField for
        -- that so the user can display filter by it (though it's kinda silly for a Pcap file)
        entrytype = ProtoField.string ("pcapfile.entry.type", "Pcap Entry Type"),
        entrysize = ProtoField.uint8  ("pcapfile.entry.size", "Pcap Entry Size"),
    },

    -- the Pcap file header fields - for all known pcap file types (I think?)
    filehdr =
    {
        magic     = ProtoField.uint32 ("pcapfile.magic", "Magic Value", base.HEX,
                                       magic_valstr, 0, "The magic 4 bytes identifying this as a pcap file"),
        major     = ProtoField.uint16 ("pcapfile.version.major", "Major Version Number"),
        minor     = ProtoField.uint16 ("pcapfile.version.minor", "Minor Version Number"),
        timezone  = ProtoField.int32  ("pcapfile.timezone", "Timezone", base.DEC,
                                       nil, 0, "GMT to local correction"),
        sigfigs   = ProtoField.uint32 ("pcapfile.sigfigs", "Significant Figures", base.DEC,
                                       nil, 0, "Accuracy of timestamps"),
        snaplen   = ProtoField.uint32 ("pcapfile.snaplen", "Snapshot Length", base.DEC,
                                       nil, 0, "Max length of captured packets, in octets"),
        linktype  = ProtoField.uint32 ("pcapfile.linktype", "Link Type", base.DEC,
                                       LINKTYPE.valstr, 0, "Pcap Link Type (LINKTYPE not DLT)"),
        dlt       = ProtoField.uint32 ("pcapfile.dlt", "Data Link Type", base.DEC,
                                       LINKTYPE.dlt.valstr, 0, "Pcap Data Link Type (DLT not LINKTYPE)"),

        -- the following are generated based on above rather than from the file header contents directly
        wtap      = ProtoField.uint32 ("pcapfile.wtap", "Wtap Encap Type", base.DEC,
                                       LINKTYPE.wtap.valstr, 0, "Wtap's internal encapsulation type"),
        needphdr  = ProtoField.bool   ("pcapfile.needs_phdr", "Needs Pseudoheader", base.NONE,
                                       nil, 0, "Whether the Wtap encap type needs a pseudo-header to dissect"),
        -- this is "normal" vs. "swapped", etc. - it's the same concept as magic, but as a string field
        filetype  = ProtoField.string ("pcapfile.file_type", "Pcap File Type"),
        precision = ProtoField.uint8  ("pcapfile.time.precision", "Time Precision", base.DEC,
                                       precision_valstr, 0, "The time precision of the timestamps"),
    },

    -- the Pcap record header fields - for both "normal" Pcap files as well as Alexey
    -- Kuznetzov's modified ss991029 patched version (but not ss990915)
    -- Nokia has some variant of a pcap record header, but they don't use a different
    -- file header magic, so currently libpcap guesses it's Nokia if the first record's
    -- header is bogus as anything else. This script doesn't bother, so we won't bother
    -- having the extra Nokia record header fields either (really it's just evil!)
    --
    -- Arguably, the variants represent different "Protocols" to dissect later,
    -- but this script treats them all as "pcapfile" protocol.
    rechdr  =
    {
        -- these are generated
        recnumber = ProtoField.uint32 ("pcapfile.record.number", "Pcap Record Number"),
        recsize   = ProtoField.uint32 ("pcapfile.record.size", "Pcap Record Size"),

        -- these are in the record header
        timestamp = ProtoField.new    ("Timestamp", "pcapfile.timestamp", ftypes.ABSOLUTE_TIME),
        time_secs = ProtoField.uint32 ("pcapfile.time.secs", "Time Seconds", base.DEC,
                                       nil, 0, "Timestamp seconds portion"),
        time_nsecs= ProtoField.uint32 ("pcapfile.time.nsecs", "Time Nanoseconds", base.DEC,
                                       nil, 0, "Timestamp nanoseconds portion"),

        caplen    = ProtoField.uint32 ("pcapfile.caplen", "Captured Length"),
        origlen   = ProtoField.uint32 ("pcapfile.origlen", "Original Length"),

        -- fields for Alexey Kuznetzov's ss991029 patched versions of pcap files
        ifindex   = ProtoField.uint32 ("pcapfile.ifindex", "Interface Index",
                                       base.DEC, nil, 0, "Interface index, in *capturing* machine's"..
                                       " list of interfaces, of the interface on which this packet"..
                                       " came in."),
        protocol  = ProtoField.uint16 ("pcapfile.protocol", "Ethertype",
                                       base.HEX, nil, 0, "Ethernet packet type"),
        pkt_type  = ProtoField.uint8  ("pcapfile.pkt_type", "Ethertype",
                                       base.HEX, nil, 0, "Broadcast/multicast/etc. indication"),
        -- ss990915 version has these too, so pad becomes 3 bytes
        -- but were not going to dissect these right now, because it requires
        -- crazy heuristic guessing
        -- cpu1      = ProtoField.uint8  ("pcapfile.cpu1", "CPU-1",
        --                                base.DEC, nil, 0, "SMP debugging gunk?"),
        -- cpu2      = ProtoField.uint8  ("pcapfile.cpu2", "CPU-2",
        --                                base.DEC, nil, 0, "SMP debugging gunk?"),
        -- the following could be 1 or 3 bytes depending on if cpu1/cpu2 exist
        -- if they exist, it's 3 bytes, else 1 byte
        pad       = ProtoField.bytes  ("pcapfile.pad", "Pad",
                                       base.NONE, nil, 0, "Pad to a 4-byte boundary"),
    }
}

-- create a flat array table of the above that can be registered
local pfields = {}
for _,t in pairs(pcap_fields) do
    for k,v in pairs(t) do
        pfields[#pfields+1] = v
    end
end

-- register them
proto_pcap.fields = pfields

dprint2("pcapfile ProtoFields registered")

--------------------------------------------------------------------------------
-- expert info fields stuff, similar to proto fields above
--------------------------------------------------------------------------------
local expert_fields =
{
    filehdr =
    {
        too_short  = ProtoExpert.new("pcapfile.file_hdr.too_short.expert", "Pcap file header too short",
                                     expert.group.MALFORMED, expert.severity.ERROR),
        malformed  = ProtoExpert.new("pcapfile.file_hdr.malformed.expert", "Pcap file header malformed",
                                     expert.group.MALFORMED, expert.severity.ERROR),
        badmagic   = ProtoExpert.new("pcapfile.file_hdr.bad_magic.expert", "Pcap magic value is unknown",
                                     expert.group.PROTOCOL, expert.severity.ERROR),
        oddversion = ProtoExpert.new("pcapfile.file_hdr.odd_version.expert", "Pcap version is unusual",
                                     expert.group.PROTOCOL, expert.severity.NOTE),
        bigsnaplen = ProtoExpert.new("pcapfile.file_hdr.big_snaplen.expert", "Pcap snaplen (capture length) too big",
                                     expert.group.PROTOCOL, expert.severity.WARN),
        nosnaplen  = ProtoExpert.new("pcapfile.file_hdr.no_snaplen.expert", "Pcap snaplen (capture length) is zero",
                                     expert.group.PROTOCOL, expert.severity.WARN),
        linktype   = ProtoExpert.new("pcapfile.file_hdr.linktype.expert", "Pcap linktype is unknown",
                                     expert.group.PROTOCOL, expert.severity.WARN),
        no_wtap    = ProtoExpert.new("pcapfile.file_hdr.no_wtap.expert", "There is no wtap type for this linktype",
                                     expert.group.PROTOCOL, expert.severity.WARN),
    },

    rechdr  =
    {
        too_short  = ProtoExpert.new("pcapfile.record.too_short.expert", "Pcap record too short",
                                     expert.group.MALFORMED, expert.severity.ERROR),
        malformed  = ProtoExpert.new("pcapfile.record.malformed.expert", "Pcap record malformed",
                                     expert.group.MALFORMED, expert.severity.ERROR),
        neg_time   = ProtoExpert.new("pcapfile.record.negative_time.expert", "Capture timestamp is less than previous frame",
                                     expert.group.SEQUENCE, expert.severity.WARN),
        pseudohdr  = ProtoExpert.new("pcapfile.record.subdissector.expert", "Record data cannot be sub-dissected due to needing a pseudo-header",
                                     expert.group.UNDECODED, expert.severity.WARN),
        sliced     = ProtoExpert.new("pcapfile.record.sliced.expert", "Capture length is less than original length",
                                     expert.group.UNDECODED, expert.severity.NOTE),
    }
}

-- create a flat array table of the above that can be registered
local efields = {}
for _,t in pairs(expert_fields) do
    for k,v in pairs(t) do
        efields[#efields+1] = v
    end
end

-- register them
proto_pcap.experts = efields

dprint2("pcapfile Expert fields registered")

--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

-- a "enum" table for our enum pref, as required by Pref.enum()
-- having the "index" number makes ZERO sense, and is completely illogical
-- but it's what the code has expected it to be for a long time. Ugh.
local encap_pref_enum = {
    { 1,  "USER0",  wtap_encaps.USER0  },
    { 2,  "USER1",  wtap_encaps.USER1  },
    { 3,  "USER2",  wtap_encaps.USER2  },
    { 4,  "USER3",  wtap_encaps.USER3  },
    { 5,  "USER4",  wtap_encaps.USER4  },
    { 6,  "USER5",  wtap_encaps.USER5  },
    { 7,  "USER6",  wtap_encaps.USER6  },
    { 8,  "USER7",  wtap_encaps.USER7  },
    { 9,  "USER8",  wtap_encaps.USER8  },
    { 10, "USER9",  wtap_encaps.USER9  },
    { 11, "USER10", wtap_encaps.USER10 },
    { 12, "USER11", wtap_encaps.USER11 },
    { 13, "USER12", wtap_encaps.USER12 },
    { 14, "USER13", wtap_encaps.USER13 },
    { 15, "USER14", wtap_encaps.USER14 },
    { 16, "USER15", wtap_encaps.USER15 },
}

local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}

----------------------------------------
-- register our preferences
proto_pcap.prefs.subdissect = Pref.bool("Enable sub-dissectors", default_settings.subdissect,
                                        "Whether the Pcap file's frame content"..
                                        " should be dissected or not")

proto_pcap.prefs.encap_type = Pref.enum("Encap type", default_settings.encap_type,
                                        "The USER# encapsulation type to use", encap_pref_enum)

proto_pcap.prefs.debug      = Pref.enum("Debug", default_settings.debug_level,
                                        "The debug printing level", debug_pref_enum)

proto_pcap.prefs._note_et   = Pref.statictext("Note: changing the encap type may not take"..
                                              " effect until the file is closed and re-opened.")

----------------------------------------
-- a function for handling prefs being changed
function proto_pcap.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.subdissect  = proto_pcap.prefs.subdissect

    default_settings.debug_level = proto_pcap.prefs.debug
    reset_debug_level()

    if default_settings.encap_type ~= proto_pcap.prefs.encap_type then
        -- remove old one
        DissectorTable.get("wtap_encap"):remove(default_settings.encap_type, proto_pcap)
        -- set our new default
        default_settings.encap_type = proto_pcap.prefs.encap_type
        -- add new one
        DissectorTable.get("wtap_encap"):add(default_settings.encap_type, proto_pcap)
        -- have to reload the capture file for this type of change
        reload()
    end

end

dprint2("pcapfile Prefs registered")


----------------------------------------
-- state/setting information the dissectors need, will be filled in later
local dissector_settings

-- this is a constant for minimum we need to read/dissect before we figure out the filetype
local FILE_HDR_LEN = 24
-- snaplen/caplen can't be bigger than this
local WTAP_MAX_PACKET_SIZE = 65535

--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- the pcapfile protocol dissector
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

-- The following creates the callback function for the dissector.
-- It's the same as doing "dns.dissector = function (tvbuf,pkt,root)"
-- The 'tvbuf' is a Tvb object, 'pktinfo' is a Pinfo object, and 'root' is a TreeItem object.
-- Whenever Wireshark dissects a packet that our Proto is hooked into, it will call
-- this function and pass it these arguments for the packet it's dissecting.
function proto_pcap.dissector(tvbuf, pktinfo, root)
    dprint2("proto_pcap.dissector called")

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("PcapFile")

    -- We want to check that the packet size is rational during dissection, so let's
    -- get the length of the packet buffer (Tvb).
    -- we can use tvb:len() or tvb:reported_length_remaining() here; but I prefer
    -- tvb:len() as it's safer.
    local pktlen = tvbuf:len()

    -- We start by adding our protocol to the dissection display tree.
    -- A call to tree:add() returns the child created, so we can add more "under" it using
    -- that return value.
    -- The second argument is how much of the buffer/packet this added tree item
    -- covers/represents - in this case that's the remainder of the packet.
    local tree = root:add(proto_pcap, tvbuf:range(0,pktlen))

    if pktinfo.number == 1 then
        -- I'm cheating doing it this way, but the first frame is a file header
        return dissect_pcap_file_hdr(tvbuf, pktinfo, tree, pktlen)
    end

    -- now let's check it's not too short
    if pktlen < dissector_settings.rec_hdr_len then
        -- since we're going to add this protocol to a specific USER13 encap type, we're
        -- going to assume packets in this port are our protocol, so the packet being
        -- too short is an error
        tree:add_expert_proto_info( expert_fields.rechdr.too_short )
        dprint("record header length", pktlen, "too short")
        return
    end

    -- looks good, go dissect it
    if dissector_settings.dissector(tvbuf, pktinfo, tree, pktlen) then
        dprint2("record header successfully dissected")
        -- ok now the hard part - try calling a sub-dissector?
        -- only if settings/prefs told us to of course...
        if default_settings.subdissect then
            -- only if it doesn't need a psuedo-header
            if not LINKTYPE.info[dissector_settings.linktype].needphdr then
                dprint2("trying sub-dissector for wtap encap type:", dissector_settings.wtap_type)

                local tvb = tvbuf(dissector_settings.rec_hdr_len, pktlen - dissector_settings.rec_hdr_len):tvb()

                DissectorTable.get("wtap_encap"):try(dissector_settings.wtap_type, tvb, pktinfo, root)
            else
                dprint2("needs pseud-header, sub-dissection cannot be performed for linktype:",dissector_settings.linktype)
                tree:add_expert_proto_info( expert_fields.rechdr.pseudohdr )
            end
        end
    else
        dprint("record header not correctly dissected")
    end
end

-- now register our protocol against the USER13 encap type
DissectorTable.get("wtap_encap"):add(default_settings.encap_type, proto_pcap)

dprint2("Protocol registered for", default_settings.encap_type, "encap type")

-- We're done with the Protocol part!
-- our Proto gets automatically fully registered after this script finishes loading
----------------------------------------

--------------------------------------------------------------------------------
-- ok now for the boring stuff that actually does the dissection work
--------------------------------------------------------------------------------

----------------------------------------
-- dissect the pcap file header
dissect_pcap_file_hdr = function(tvbuf, pktinfo, tree, pktlen)
    dprint2("dissect_pcap_file_hdr called")

    -- set the INFO column
    pktinfo.cols.info:set("File Header")

    -- let's add the common things every frame gets
    tree:add(pcap_fields.common.entrytype, "File Header"):set_generated()

    -- the following can't really happen because our file reader wouldn't
    -- have read the file if this were true, but this is good practice
    if (tvbuf:len() < FILE_HDR_LEN) then
        tree:add_expert_proto_info( expert_fields.filehdr.too_short )
        dprint("Not enough bytes for a file header; got:", tvbuf:len())
        return false
    end

    tree:add(pcap_fields.common.entrysize, FILE_HDR_LEN):set_generated()

    -- The magic starts at offset 0, for 4 bytes length
    dissector_settings = create_magic_settings(tvbuf:range(0,4):uint())

    if not dissector_settings then
        -- add it to the tree anyway so user sees it
        tree:add(pcap_fields.filehdr.magic, tvbuf:range(0,4))
        -- now highlight the bad magic in our expert info
        tree:add_tvb_expert_info( expert_fields.filehdr.badmagic, tvbuf:range(0,4) )
        dprint("magic was: '", Struct.tohex(magic), "', so not a known pcap file?")
        return false
    end

    tree:add(pcap_fields.filehdr.filetype, dissector_settings.name):set_generated()

    -- we don't want to fix the endianness of this, so use normal tree:add()
    tree:add(pcap_fields.filehdr.magic, tvbuf:range(0,4))

    -- get the endian-appropriate tree:add() and tvb:uint() functions
    local add  = dissector_settings.add
    local uint = dissector_settings.uint

    -- version info
    add(tree, pcap_fields.filehdr.major, tvbuf:range(4,2))
    add(tree, pcap_fields.filehdr.minor, tvbuf:range(6,2))

    if uint(tvbuf:range(4,2)) ~= 2 or uint(tvbuf:range(6,2)) ~= 4 then
        tree:add_tvb_expert_info( expert_fields.filehdr.oddversion, tvbuf:range(4,4) )
    end

    -- etc., etc.
    add(tree, pcap_fields.filehdr.timezone, tvbuf:range(8,4))
    add(tree, pcap_fields.filehdr.sigfigs,  tvbuf:range(12,4))
    add(tree, pcap_fields.filehdr.snaplen,  tvbuf:range(16,4))

    local snaplen = uint(tvbuf:range(16,4))

    if snaplen > WTAP_MAX_PACKET_SIZE then
        tree:add_tvb_expert_info( expert_fields.filehdr.bigsnaplen, tvbuf:range(16,4) )
    elseif snaplen == 0 then
        tree:add_tvb_expert_info( expert_fields.filehdr.nosnaplen, tvbuf:range(16,4) )
    end

    tree:add(pcap_fields.filehdr.precision, dissector_settings.time_precision):set_generated()

    -- linktype and dlt are the same (final) 4 bytes
    -- they have value-string tables which differ
    add(tree, pcap_fields.filehdr.linktype, tvbuf:range(20,4))
    add(tree, pcap_fields.filehdr.dlt,      tvbuf:range(20,4))

    -- now add the generated wtap number, based on the linktype
    -- we're using our local 'uint' function which is set to either
    -- TvbRange.uint() or le_uint() depending on endianness
    local linktype = uint(tvbuf:range(20,4))

    dissector_settings.linktype = linktype

    -- get the type info table
    local type_info = LINKTYPE.info[linktype]

    if not type_info then
        -- linktype unknown, generate expert info
        tree:add_tvb_expert_info( expert_fields.filehdr.linktype, tvbuf:range(20,4) )
        -- create a dummy table so later functions work
        type_info = {}
    end

    -- convert the linktype to its wtap string name, so that we can
    -- then lookup the string name in the wtap_encaps directory
    -- of course we could have just done this mapping in the LINKTYPE
    -- table itself during load, but I'm incompetent
    local wtapname = LINKTYPE.wtap.valstr[linktype]
    if wtapname then
        dissector_settings.wtap_type = wtap_encaps[wtapname] or wtap_encaps.UNKNOWN
    end

    if dissector_settings.wtap_type == wtap_encaps.UNKNOWN then
        tree:add_tvb_expert_info( expert_fields.filehdr.nosnaplen, tvbuf:range(20,4) )
    end

    -- add the wtap name to the INFO column
    if not wtapname then wtapname = "UNKNOWN" end
    pktinfo.cols.info:append(" (" .. wtapname .. ")")

    -- note, the following uses a new feature in 1.11.3: set_generated() returns the same tree
    local subtree = tree:add(pcap_fields.filehdr.wtap, linktype):set_generated()

    -- note: the following uses a bug-fixed feature of tree:add() in 1.11.3: to let a booolean
    -- field type take a nil or booolean value
    subtree:add(pcap_fields.filehdr.needphdr, type_info.needphdr):set_generated()

    local info = type_info.comments or "No information - unknown"
    subtree:add("Wtap details: " .. info):set_generated()

end

----------------------------------------
-- dissect a pcap record header (normal, swapped, nsec)
dissect_pcap_record = function(tvbuf, pktinfo, tree, pktlen)
    dprint2("dissect_pcap_record called")

    -- set the INFO column
    pktinfo.cols.info:set("Record (" .. (pktinfo.number - 1) .. ")")

    -- get the endian-appropriate tree:add() function
    local add = dissector_settings.add

    -- let's add the common things every frame gets
    add(tree, pcap_fields.common.entrytype, "Record Header"):set_generated()
    add(tree, pcap_fields.common.entrysize, dissector_settings.rec_hdr_len):set_generated()

    add(tree, pcap_fields.rechdr.recnumber, pktinfo.number - 1):set_generated()

    add(tree, pcap_fields.rechdr.recsize, pktlen):set_generated()

    local subtree = add(tree, pcap_fields.rechdr.timestamp, tvbuf:range(0,8))
    add(subtree, pcap_fields.rechdr.time_secs, tvbuf:range(0,4))
    add(subtree, pcap_fields.rechdr.time_nsecs,tvbuf:range(4,4))

    add(tree, pcap_fields.rechdr.caplen, tvbuf:range(8,4))
    add(tree, pcap_fields.rechdr.origlen, tvbuf:range(12,4))

    return true
end 

----------------------------------------
-- dissect a modified pcap record header
-- this only dissects patch ss991029 right now
dissect_pcap_modified_record = function(tvbuf, pktinfo, tree, pktlen)
    dprint2("dissect_pcap_modified_record called")

    -- call the regular pcap record header dissector first
    if not dissect_pcap_record(tvbuf, pktinfo, tree, pktlen) then
        dprint("dissect_pcap_modified_record: dissect_pcap_record failed")
        return false
    end

    -- get the endian-appropriate tree:add() function
    local add = dissector_settings.add

    add(tree, pcap_fields.rechdr.ifindex,  tvbuf:range(16,4))
    add(tree, pcap_fields.rechdr.protocol, tvbuf:range(20,2))
    add(tree, pcap_fields.rechdr.pkt_type, tvbuf:range(22,1))
    add(tree, pcap_fields.rechdr.pad,      tvbuf:range(23,1))

    return true
end



--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
-- file reader handling functions for Wireshark to use
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------

----------------------------------------
-- to make it easier to read this file, we'll define some of the functions
-- later on, but we need them earlier, so we "declare" them here
local read_open_file_header, read_rec_header, read_common_record, read_common_file_hdr

----------------------------------------
-- The read_open() is called by Wireshark once per file, to see if the file is this reader's type.
-- Wireshark passes in (1) a File object and (2) CaptureInfo object to this function
-- It expects in return either nil or false to mean it's not our file type, or true if it is
-- In our case what this means is we figure out if the file has the magic header, and get the
-- endianness of the file, and the encapsulation type of its frames/records
-- Since Wireshark uses the file cursor position for future reading of this file, we also have
-- to seek back to the beginning so that our normal read() function works correctly.
local function read_open(file, capture)
    dprint2("read_open() called")

    -- save current position to return later
    local position = file:seek()

    local file_settings = read_open_file_header(file)

    if file_settings then

        dprint2("read_open: success, file is for us")

        -- save our state
        capture.private_table = file_settings

        -- try parsing the first record header too to get the time
        -- if it fails we don't care
        -- we pass in a table as the fourth arg, so that the read_rec_header()
        -- thinks it's getting a FrameInfo object to set attributes to
        read_rec_header("read_open", file, file_settings, {})

        -- if the file is for us, we MUST set the file position cursor to
        -- where we want the first call to read() function to get it the next time
        -- for example if we checked a few records to be sure it's or type
        -- in this script we only verify the file header (24 bytes)
        -- BUT we want the file position to be back at the file header after read()
        -- call... so we seek it back here
        file:seek("set",position)

        -- these we can also set per record later during read operations
        -- but for Pcap files, it's in the file header, so we set it now
        -- note that the right-hand side variables were updated by read_open_file_header()
        capture.time_precision  = file_settings.time_precision
        capture.encap           = file_settings.encap_type
        capture.snapshot_length = file_settings.snaplen

        return true
    end

    dprint2("read_open: file not for us")

    -- if it's not for us, wireshark will reset the file position itself

    return false
end

----------------------------------------
-- Wireshark/tshark calls read() for each frame/record in the file
-- It passes in a File object and FrameInfo object to this function
-- It expects in return the file offset position the record starts at,
-- or nil/false if there's an error or end-of-file is reached.
-- The offset position is used later: Wireshark remembers it and gives
-- it to seek_read() at various random times
local function read(file, capture, frame)
    dprint2("read() called")

    local position = file:seek()

    -- call our common reader functions.
    -- if the position is 0, then this is a file header we're being asked
    -- to read; in that case, we have nothing to learn from it (we already
    -- parsed it in the read_open() call). So we have a different function
    if position == 0 then
        if not read_common_file_hdr("read", file, capture, frame) then
            dprint("read: failed to call read_common_file_hdr")
            return false
        end
    elseif not read_common_record("read", file, capture, frame) then
        -- this isnt' actually an error, because it might just mean we reached end-of-file
        -- so let's test for that (read(0) is a special case in Lua, see Lua docs)
        if file:read(0) ~= nil then
            dprint("read: failed to call read_common_record")
        else
            dprint2("read: reached end of file")
        end
        return false
    end

    dprint2("read: succeess")

    -- return the position we got to (or nil if we hit EOF/error)
    return position
end

----------------------------------------
-- Wireshark/tshark calls seek_read() for each frame/record in the file, at random times
-- It passes in to this function a File object, FrameInfo object, and the offset position number
-- It expects in return true for successful parsing, or nil/false if there's an error.
local function seek_read(file, capture, frame, offset)
    dprint2("seek_read() called")

    -- first move to the right position in the file
    file:seek("set",offset)

    -- now do similar things as in read()
    if offset == 0 then
        if not read_common_file_hdr("seek_read", file, capture, frame) then
            dprint("seek_read: failed to call read_common_file_hdr")
            return false
        end
    elseif not read_common_record("seek_read", file, capture, frame) then
        dprint("seek_read: failed to call read_common")
        return false
    end

    return true
end

----------------------------------------
-- Wireshark/tshark calls read_close() when it's closing the file completely
-- this is a good opportunity to clean up any state you may have created during
-- file reading. (in our case the file settings are state)
local function read_close(file, capture)
    dprint2("read_close() called")
    -- we don't really have to reset these, because we do this in read_open() as well
    return true
end

----------------------------------------
-- An often unused function, Wireshark calls this when the sequential walk-through is over
-- (i.e., no more calls to read(), only to seek_read()). This is also called right before
-- read_close() is called, so it will be called twice: once during reading, and again
-- when the file is finally closed (user quit, or opened a different file, etc.).
-- This gives you a chance to clean up any state you used during read() calls, but remember
-- that there will be calls to seek_read() after this (in Wireshark, though not Tshark)
local function seq_read_close(file, capture)
    dprint2("seq_read_close() called")
    dprint2("First pass of read() calls are over, but there may be seek_read() calls after this")
    return true
end

----------------------------------------
-- ok, so let's create a FileHandler object
-- we set it to weak heuristic, because this is a fileshark script and we don't
-- want it to be used in place of the normal pcap file reader
-- the user will have to explicityl request this script by selecting its file type
local fh = FileHandler.new ("Fileshark PCAP reader", "Fileshark Pcap",
                            "A Lua-based fileshark reader for PCAP-type files", "rs")

-- set above functions to the FileHandler
fh.read_open = read_open
fh.read = read
fh.seek_read = seek_read
fh.read_close = read_close
fh.seq_read_close = seq_read_close
fh.extensions = "pcap;cap" -- this is just a hint

-- and finally, register the FileHandler!
register_filehandler(fh)

dprint2("Pcap Fileshark FileHandler registered")

--------------------------------------------------------------------------------
-- ok now for the boring stuff that actually does the file reading work
--------------------------------------------------------------------------------

----------------------------------------
-- some variables used and set after parsing a file header
--
-- we'll create some defaults we always reset to
-- and then a copy of those that get change per file

-- here are the "structs" we're going to parse, of the various records in a pcap file
-- these pattern string gets used in calls to Struct.unpack()
--
-- we will prepend a '<' or '>' later, once we figure out what endianness the files are in
--
-- a pcap file header struct
-- this is: magic, version_major, version_minor, timezone, sigfigs, snaplen, encap type
local FILE_HEADER_PATT = "I4 I2 I2 i4 I4 I4 I4"
-- it's too bad Struct doesn't have a way to get the number of vars the pattern holds
-- another thing to add to my to-do list?
local NUM_HDR_FIELDS = 7

----------------------------------------
-- internal functions declared previously
----------------------------------------

----------------------------------------
-- used by read_open(), this reads and parses the file header
-- we MUST be able to (1) read a full file header, and (2) read a magic value
-- we understand. Even though this is fileshark, it only makes sense to have
-- some minimum requirement to read a file
read_open_file_header = function(file)
    dprint2("read_open_file_header() called")

    -- by default, file:read() gets the next "string", meaning ending with a newline \n
    -- but we want raw byte reads, so tell it how many bytes to read
    local line = file:read(FILE_HDR_LEN)

    -- it's ok for us to not be able to read it, but we need to tell wireshark the
    -- file's not for us, so return false
    if not line then return false end

    dprint2("read_open_file_header: got this line:\n'", Struct.tohex(line,false,":"), "'")

    -- let's peek at the magic int32, assuming it's big-endian
    local magic = Struct.unpack(">I4", line)

    local file_settings = create_magic_settings(magic)

    if not file_settings then
        dprint("magic was: '", magic, "', so not a known pcap file?")
        return false
    end

    -- this is: magic, version_major, version_minor, timezone, sigfigs, snaplen, encap type
    local fields = { Struct.unpack(file_settings.file_hdr_patt, line) }

    -- sanity check; also note that Struct.unpack() returns the fields plus
    -- a number of where in the line it stopped reading (i.e., the end in this case)
    -- so we got back number of fields + 1
    if #fields ~= NUM_HDR_FIELDS + 1 then
        -- this should never happen, since we already told file:read() to grab enough bytes
        dprint("read_open_file_header: failed to read the file header")
        return nil
    end

    -- fields[1] is the magic, which we already parsed and saved before, but just to be sure
    -- our endianness is set right, we validate what we got is what we expect now that
    -- endianness has been corrected
    if fields[1] ~= file_settings.corrected_magic then
        dprint ("read_open_file_header: endianness screwed up? Got:'", fields[1],
                "', but wanted:", file_settings.corrected_magic)
        return nil
    end

    file_settings.version_major = fields[2]
    file_settings.version_minor = fields[3]
    file_settings.timezone      = fields[4]
    file_settings.sigfigs       = fields[5]
    file_settings.read_snaplen  = fields[6]
    file_settings.linktype      = fields[7]

    local wtapname = LINKTYPE.wtap.valstr[file_settings.linktype]
    if wtapname then
        file_settings.wtap_type = wtap_encaps[wtapname] or wtap_encaps.UNKNOWN
    end

    file_settings.snaplen = file_settings.read_snaplen
    if file_settings.snaplen > WTAP_MAX_PACKET_SIZE then
        file_settings.snaplen = WTAP_MAX_PACKET_SIZE
    end

    dprint2("read_open_file_header: got magic='", magic,
            "', major version='", file_settings.version_major,
            "', minor='", file_settings.version_minor,
            "', timezone='", file_settings.timezone,
            "', sigfigs='", file_settings.sigfigs,
            "', read_snaplen='", file_settings.read_snaplen,
            "', snaplen='", file_settings.snaplen,
            "', nettype ='", file_settings.linktype)

    --ok, it's a pcap file
    dprint2("read_open_file_header: success")
    return file_settings
end

----------------------------------------
-- this is used by both read() and seek_read()
-- the calling function to this should have already set the file position correctly
read_common_file_hdr = function(funcname, file, capture, frame)
    dprint2(funcname,": read_common_file_hdr() called")
    -- we already parsed everything important in the read_open()
    -- so this just sets the things that apply to this "frame" and
    -- then reads it all in as "data"

    local file_settings = capture.private_table

    -- we could just do this:
    --frame.time = file_settings.time_secs + (file_settings.time_nsecs / 1000000000)
    -- but Lua numbers are doubles, which lose precision in the fractional part
    -- so we use a NSTime() object instead
    frame.time = NSTime(file_settings.time_secs, file_settings.time_nsecs)

    if not frame:read_data(file, FILE_HDR_LEN) then
        -- this should be impossible
        dprint(funcname, ": read_common_file_hdr: failed to read data from file into buffer")
        return false
    end

    frame.captured_length = FILE_HDR_LEN
    frame.original_length = FILE_HDR_LEN

    -- this is a hacky way to do timestamp|cap_len, but Lua has no bit OR op in 5.1
    frame.flags = wtap_presence_flags.TS + wtap_presence_flags.CAP_LEN

    dprint2(funcname,": read_common_file_hdr() returning")
    return true
end

----------------------------------------
-- the following reads a whole record
-- this calls read_rec_header(), which was split out so that read_open() could call
-- it separately.
-- this is used by both read() and seek_read()
-- the calling function to this should have already set the file position correctly
read_common_record = function(funcname, file, capture, frame)
    dprint2(funcname,": read_common_record() called")

    -- get current file position for later
    local position = file:seek()

    local file_settings = capture.private_table

    -- first parse the record header, which will set the FrameInfo fields
    if not read_rec_header(funcname, file, file_settings, frame) then
        dprint2(funcname, ": read_common_record: hit end of file or error")
        return false
    end

    -- this is probably unecessary, since we didn't set wtap_encaps.PER_PACKET
    frame.encap = file_settings.encap_type

    -- now we need to get the packet bytes from the file record into the frame...
    -- we *could* read them into a string using file:read(numbytes), and then
    -- set them to frame.data so that wireshark gets it...
    -- but that would mean the packet's string would be copied into Lua
    -- and then sent right back into wireshark, which is gonna slow things
    -- down; instead FrameInfo has a read_data() method, which makes
    -- wireshark read directly from the file into the frame buffer, so we use that
    -- but first we set file position back, so we read the record header into
    -- the "frame" buffer as well, so our dissector gets it
    file:seek("set",position)

    if not frame:read_data(file, frame.captured_length) then
        dprint(funcname, ": read_common_record: failed to read data from file into buffer")
        return false
    end

    dprint2(funcname,": read_common_record() returning")
    return true
end

----------------------------------------
-- the function to read/parse individual record headers
-- this was split out from read_common_record so that read_open() could call
-- this one separately.
-- unlike normal file reading, we need to let this fail as gracefully as possible
-- i.e., we need to accept completely malformed record headers and deal with it
-- because one purpose of fileshark is to be able to see what may be wrong in a file
read_rec_header = function(funcname, file, file_settings, frame)
    dprint2(funcname,": read_rec_header() called")

    -- file:read() does not seek back if it fails, so we need to save
    -- the current file position
    local position = file:seek()

    local line = file:read(file_settings.rec_hdr_len)

    -- it's ok for us to not be able to read it, if it's end of file
    if not line then
        if file:read(0) == nil then
            dprint2(funcname,": read_rec_header: reached end of file")
            return false
        else
            dprint2(funcname,": read_rec_header: could not read full record header")
            -- assume the frame's time is the file's time, which might be zero-hour
            frame.time = NSTime(file_settings.time_secs, file_settings.time_nsecs)
            -- just grab everything remaining
            file:seek("set", position)
            line = file:read("*all")
            -- set lengths to whatever was remaining
            frame.captured_length = line:len()
            frame.original_length = line:len()
            frame.flags = 0 -- reset presence flags
            dprint2(funcname,": read_rec_header: returning true for partial record header")
            return true
        end
    end

    -- we got a whole line, yeah!

    -- this is: time_sec, time_usec, capture_len, original_len
    local fields = { Struct.unpack(file_settings.rec_hdr_patt, line) }

    -- sanity check; also note that Struct.unpack() returns the fields plus
    -- a number of where in the line it stopped reading (i.e., the end in this case)
    -- so we got back number of fields + 1
    if #fields ~= file_settings.num_rec_fields + 1 then
        -- this should be impossible
        dprint(funcname, ": read_rec_header: failed to read the record header")
        return nil
    end

    local nsecs = fields[2]

    if file_settings.time_precision == wtap_filetypes.TSPREC_USEC then
        nsecs = nsecs * 1000
    elseif file_settings.time_precision == wtap_filetypes.TSPREC_MSEC then
        nsecs = nsecs * 1000000
    end

    frame.time = NSTime(fields[1], nsecs)

    -- if this is the first record, set the file's times to it
    if file_settings.time_secs == 0 then
        file_settings.time_secs = fields[1]
        file_settings.time_nsecs = nsecs
    end

    local caplen, origlen = fields[3], fields[4]

    -- sanity check, verify captured length isn't more than original length
    if caplen > origlen then
        dprint("captured length of", caplen, "is bigger than original length of", origlen)
        -- swap them, a cool Lua ability
        caplen, origlen = origlen, caplen
    end

    -- add the record header length
    caplen  = caplen  + file_settings.rec_hdr_len
    origlen = origlen + file_settings.rec_hdr_len

    if caplen > WTAP_MAX_PACKET_SIZE then
        dprint("Got a captured_length of", caplen, "which is too big")
        caplen = WTAP_MAX_PACKET_SIZE
    end

    frame.captured_length = caplen
    frame.original_length = origlen

    frame.flags = wtap_presence_flags.TS + wtap_presence_flags.CAP_LEN -- for timestamp|cap_len

    dprint2(funcname,": read_rec_header() returning")
    return true
end

----------------------------------------
-- set the settings that the magic value defines in magic_values
create_magic_settings = function(magic)
    local t = magic_values[magic]
    if not t then
        dprint("create_magic_settings: did not find magic settings for:",magic)
        return false
    end

    local settings = new_settings()

    -- the magic_values/spells table uses the same key names, so this is easy
    for k,v in pairs(t) do
        settings[k] = v
    end

    -- based on endianness, set the file_header and rec_header
    -- and determine corrected_magic
    if settings.endianness == ENC_BIG_ENDIAN then
        settings.file_hdr_patt = '>' .. FILE_HEADER_PATT
        settings.rec_hdr_patt  = '>' .. settings.rec_hdr_patt
        settings.corrected_magic = magic
    else
        settings.file_hdr_patt = '<' .. FILE_HEADER_PATT
        settings.rec_hdr_patt  = '<' .. settings.rec_hdr_patt
        settings.corrected_magic = Struct.unpack("<I4", Struct.pack(">I4", magic))
        settings.add, settings.uint = TreeItem.add_le, TvbRange.le_uint
    end

    settings.rec_hdr_len = Struct.size(settings.rec_hdr_patt)

    return settings
end

