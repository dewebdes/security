----------------------------------------
-- linktype.lua
-- Author: Hadriel Kaplan
-- License: the code itself is Public Domain or MIT license - your choice
--          but the text which comprises most of this comes from:
--          http://www.tcpdump.org/linktypes.html
--
-- Overview:
-- In Wireshark's Lua, we have access to encapsulation types in the 'wtap_encaps' table,
-- but those numbers don't actually necessarily match the numbers in pcap files for
-- the encapsulation type, because the namespace got screwed up at some point in
-- the past (blame LBL NRG, not wireshark for that).  So there are multiple number
-- spaces in Wireshark: the one encoded in Pcap files, and the ones Wireshark uses
-- internally.  The former are "linktypes" in this file, and the latter are "wtap".
--
-- This file provides an info mapping table and a few key'ed tables based off of it.
-- It's purpose is to map linktypes to wtaps, as well as provide some info about them.
--
-- The table of PCAP file linktype value information is scraped from both
--   wiretap/pcap-common.h as well as http://www.tcpdump.org/linktypes.html
--
-- This file is intended to be called with a 'require' statement.

-- the table we'll be returning at the end of the file
local linktype = {}


-------------------------------------------------
-- the table keys are the linktype numbers
-- the linktype field is the LINKTYPE name per the above URL
-- the dlt field is the DLT name per the above URL
-- the wtap field is Wireshark-s internal name, which can then be mapped to the
--   internal number by looking this name up in the wtap_encaps table (see init.lua)
-- the comments are scraped from the above sources
-- this table is used to buld value-string tables later, as well as to display
--   extra information in the tree
linktype.info =
{
    [ 0 ]   = {
                linktype = "LINKTYPE_NULL",
                dlt      = "DLT_NULL",
                wtap     = "NULL",
                comments = "BSD loopback encapsulation; the link layer header is a"..
                            " 4-byte field, in host byte order, containing a PF_"..
                            " value from socket.h for the network-layer protocol"..
                            " of the packet."
              },
    [ 1 ]   = {
                linktype = "LINKTYPE_ETHERNET",
                dlt      = "DLT_EN10MB",
                wtap     = "ETHERNET",
                comments = "IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up);"..
                           " the 10MB in the DLT_ name is historical."
              },
    [ 3 ]   = {
                linktype = "LINKTYPE_AX25",
                dlt      = "DLT_AX25",
                wtap     = "AX25",
                comments = "AX.25 packet, with nothing preceding it."
              },
    [ 6 ]   = {
                linktype = "LINKTYPE_IEEE802_5",
                dlt      = "DLT_IEEE802",
                wtap     = "TOKEN_RING",
                comments = "IEEE 802.5 Token Ring; the IEEE802, without _5, in"..
                           " the DLT_ name is historical."
              },
    [ 7 ]   = {
                linktype = "LINKTYPE_ARCNET_BSD",
                dlt      = "DLT_ARCNET",
                wtap     = "ARCNET",
                comments = "ARCNET Data Packets, as described by the ARCNET Trade"..
                           " Association standard ATA 878.1-1999, but without the"..
                           " Starting Delimiter, Information Length, or Frame Check"..
                           " Sequence fields, and with only the first ISU of the"..
                           " Destination Identifier. For most packet types, ARCNET"..
                           " Trade Association draft standard ATA 878.2 is also"..
                           " used. See also RFC 1051 and RFC 1201; for RFC 1051"..
                           " frames, ATA 878.2 is not used."
              },
    [ 8 ]   = {
                linktype = "LINKTYPE_SLIP",
                dlt      = "DLT_SLIP",
                wtap     = "SLIP",
                comments = "SLIP, encapsulated with a LINKTYPE_SLIP header."
              },
    [ 9 ]   = {
                linktype = "LINKTYPE_PPP",
                dlt      = "DLT_PPP",
                wtap     = "PPP",
                comments = "PPP, as per RFC 1661 and RFC 1662; if the first 2 bytes"..
                           " are 0xff and 0x03, it's PPP in HDLC-like framing,"..
                           " with the PPP header following those two bytes, otherwise"..
                           " it's PPP without framing, and the packet begins with"..
                           " the PPP header."
              },
    [ 10 ]  = {
                linktype = "LINKTYPE_FDDI",
                dlt      = "DLT_FDDI",
                wtap     = "FDDI",
                comments = "FDDI, as specified by ANSI INCITS 239-1994."
              },
    [ 11 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "ATM_RFC1483",
                comments = "Technically reserved, but apparently can be ATM_RFC1483."
              },
    [ 12 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "RAW_IP",
                comments = "Technically reserved, but apparently DLT_RAW on most"..
                            " platforms, but it's DLT_C_HDLC on BSD/OS, and DLT_LOOP"..
                            " on OpenBSD."
              },
    [ 13 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "ENC",
                comments = "Technically reserved, but apparently OpenBSD enc(4)"..
                           " encapsulating interface on most platforms."
              },
    [ 14 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "RAW_IP",
                comments = "Technically reserved, but apparently RAW_IP on BSD/OS and OpenBSD."
              },
    [ 16 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "LINUX_ATM_CLIP",
                comments = "Classical IP frame (unique to Wireshark?). This Linktype is"..
                           " also DLT_PPP_BSDOS on BSD/OS; DLT_HDLC on NetBSD (Cisco"..
                           " HDLC); and DLT_I4L_IP with the ISDN4Linux patches for libpcap"
              },
    [ 17 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "OLD_PFLOG",
                comments = "Technically reserved, but apparently used as the PF (Packet"..
                           " Filter) logging format beginning with OpenBSD 3.0."
              },
    [ 18 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "LINUX_ATM_CLIP",
                comments = "Technically reserved, but apparently classical IP frame."
              },
    [ 19 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "LINUX_ATM_CLIP",
                comments = "Technically reserved, but apparently classical IP frame."
              },
    [ 32 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "REDBACK",
                comments = "Technically reserved, but apparently used by Redback"..
                           " Networks (now Ericsson)."
              },
    [ 50 ]  = {
                linktype = "LINKTYPE_PPP_HDLC",
                dlt      = "DLT_PPP_SERIAL",
                wtap     = "PPP",
                comments = "PPP in HDLC-like framing, as per RFC 1662, or Cisco"..
                           " PPP with HDLC framing, as per section 4.3.1 of RFC"..
                           " 1547; the first byte will be 0xFF for PPP in HDLC-like"..
                           " framing, and will be 0x0F or 0x8F for Cisco PPP with"..
                           " HDLC framing."
              },
    [ 51 ]  = {
                linktype = "LINKTYPE_PPP_ETHER",
                dlt      = "DLT_PPP_ETHER",
                wtap     = "PPP_ETHER",
                comments = "PPPoE; the packet begins with a PPPoE header, as per"..
                           " RFC 2516."
              },
    [ 99 ]  = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "SYMANTEC",
                comments = "Technically reserved, but apparently used by Axent"..
                           " Raptor firewall (now Symantec Enterprise Firewall)"..
                           "."
              },
    [ 100 ] = {
                linktype = "LINKTYPE_ATM_RFC1483",
                dlt      = "DLT_ATM_RFC1483",
                wtap     = "ATM_RFC1483",
                comments = "RFC 1483 LLC/SNAP-encapsulated ATM; the packet begins"..
                           " with an IEEE 802.2 LLC header."
              },
    [ 101 ] = {
                linktype = "LINKTYPE_RAW",
                dlt      = "DLT_RAW",
                wtap     = "RAW_IP",
                comments = "Raw IP; the packet begins with an IPv4 or IPv6 header"..
                           ", with the 'version' field of the header indicating"..
                           " whether it's an IPv4 or IPv6 header."
              },
    [ 104 ] = {
                linktype = "LINKTYPE_C_HDLC",
                dlt      = "DLT_C_HDLC",
                wtap     = "CHDLC",
                comments = "Cisco PPP with HDLC framing, as per section 4.3.1 of"..
                           " RFC 1547."
              },
    [ 105 ] = {
                linktype = "LINKTYPE_IEEE802_11",
                dlt      = "DLT_IEEE802_11",
                wtap     = "IEEE_802_11",
                comments = "IEEE 802.11 wireless LAN."
              },
    [ 106 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "LINUX_ATM_CLIP",
                comments = "Classical IP frame (unique to Wireshark?)."
              },
    [ 107 ] = {
                linktype = "LINKTYPE_FRELAY",
                dlt      = "DLT_FRELAY",
                wtap     = "FRELAY",
                comments = "Frame Relay"
              },
    [ 108 ] = {
                linktype = "LINKTYPE_LOOP",
                dlt      = "DLT_LOOP",
                wtap     = "NULL",
                comments = "OpenBSD loopback encapsulation; the link-layer header"..
                           " is a 4-byte field, in network byte order, containing"..
                           " a PF_ value from OpenBSD's socket.h for the network-layer"..
                           " protocol of the packet."
              },
    [ 109 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "ENC",
                comments = "OpenBSD enc(4) IPSEC encapsulating interface."
              },
    [ 110 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "UNKNOWN",
                comments = "NetBSD HIPPI (deprecated?)."
              },
    [ 111 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "UNKNOWN",
                comments = "ATM LANE 802.3 (deprecated?)."
              },
    [ 112 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "CHDLC",
                comments = "NetBSD HDLC framing based on Cisco PPP with HDLC framing,"..
                           " as per section 4.3.1 of RFC 1547."
              },
    [ 113 ] = {
                linktype = "LINKTYPE_LINUX_SLL",
                dlt      = "DLT_LINUX_SLL",
                wtap     = "SLL",
                comments = "Linux 'cooked' capture encapsulation."
              },
    [ 114 ] = {
                linktype = "LINKTYPE_LTALK",
                dlt      = "DLT_LTALK",
                wtap     = "LOCALTALK",
                comments = "Apple LocalTalk; the packet begins with an AppleTalk"..
                           " LocalTalk Link Access Protocol header, as described"..
                           " in chapter 1 of Inside AppleTalk, Second Edition."
              },
    [ 117 ] = {
                linktype = "LINKTYPE_PFLOG",
                dlt      = "DLT_PFLOG",
                wtap     = "PFLOG",
                comments = "OpenBSD pflog; the link-layer header contains a 'struct"..
                           " pfloghdr' structure, as defined by the host on which"..
                           " the file was saved. (This differs from operating system"..
                           " to operating system and release to release; there"..
                           " is nothing in the file to indicate what the layout"..
                           " of that structure is.)"
              },
    [ 118 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "CISCO_IOS",
                comments = "Cisco Router Operating System (IOS) internal."
              },
    [ 119 ] = {
                linktype = "LINKTYPE_IEEE802_11_PRISM",
                dlt      = "DLT_PRISM_HEADER",
                wtap     = "IEEE_802_11_PRISM",
                comments = "Prism monitor mode information followed by an 802.11"..
                           " header."
              },
    [ 121 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "HHDLC",
                comments = "Siemens HiPath HDLC."
              },
    [ 122 ] = {
                linktype = "LINKTYPE_IP_OVER_FC",
                dlt      = "DLT_IP_OVER_FC",
                wtap     = "IP_OVER_FC",
                comments = "RFC 2625 IP-over-Fibre Channel, with the link-layer"..
                           " header being the Network_Header as described in that RFC."
              },
    [ 123 ] = {
                linktype = "LINKTYPE_SUNATM",
                dlt      = "DLT_SUNATM",
                wtap     = "ATM_PDUS",
                comments = "ATM traffic, encapsulated as per the scheme used by"..
                           " SunATM devices.",
                needphdr = true
              },
    [ 127 ] = {
                linktype = "LINKTYPE_IEEE802_11_RADIOTAP",
                dlt      = "DLT_IEEE802_11_RADIO",
                wtap     = "IEEE_802_11_RADIOTAP",
                comments = "Radiotap link-layer information followed by an 802.11 header."
              },
    [ 128 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "TZSP",
                comments = "Tazmen Sniffer Protocol."
              },
    [ 129 ] = {
                linktype = "LINKTYPE_ARCNET_LINUX",
                dlt      = "DLT_ARCNET_LINUX",
                wtap     = "ARCNET_LINUX",
                comments = "ARCNET Data Packets, as described by the ARCNET Trade"..
                           " Association standard ATA 878.1-1999, but without the"..
                           " Starting Delimiter, Information Length, or Frame Check"..
                           " Sequence fields, with only the first ISU of the Destination"..
                           " Identifier, and with an extra two-ISU 'offset' field"..
                           " following the Destination Identifier. For most packet"..
                           " types, ARCNET Trade Association draft standard ATA"..
                           " 878.2 is also used; however, no exception frames are"..
                           " supplied, and reassembled frames, rather than fragments,"..
                           " are supplied. See also RFC 1051 and RFC 1201; for"..
                           " RFC 1051 frames, ATA 878.2 is not used."
              },
    [ 130 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_MLPPP",
                comments = "Juniper MLPPP on ML-, LS-, AS- PICs."
              },
    [ 131 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_MLFR",
                comments = "Juniper MLFR (FRF.15) on ML-, LS-, AS- PICs."
              },
    [ 133 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_GGSN",
                comments = "Juniper GGSN Node."
              },
    [ 135 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_ATM2",
                comments = "Various encapsulations captured on the ATM2 PIC."
              },
    [ 136 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_SVCS",
                comments = "Various encapsulations captured on the services PIC."
              },
    [ 137 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_ATM1",
                comments = "Various encapsulations captured on the ATM1 PIC."
              },
    [ 138 ] = {
                linktype = "LINKTYPE_APPLE_IP_OVER_IEEE1394",
                dlt      = "DLT_APPLE_IP_OVER_IEEE1394",
                wtap     = "APPLE_IP_OVER_IEEE1394",
                comments = "Apple IP-over-IEEE 1394 cooked header." 
              },
    [ 139 ] = {
                linktype = "LINKTYPE_MTP2_WITH_PHDR",
                dlt      = "DLT_MTP2_WITH_PHDR",
                wtap     = "MTP2_WITH_PHDR",
                comments = "Signaling System 7 Message Transfer Part Level 2, as"..
                           " specified by ITU-T Recommendation Q.703, preceded"..
                           " by a pseudo-header.",
                needphdr = true
              },
    [ 140 ] = {
                linktype = "LINKTYPE_MTP2",
                dlt      = "DLT_MTP2",
                wtap     = "MTP2",
                comments = "Signaling System 7 Message Transfer Part Level 2, as"..
                           " specified by ITU-T Recommendation Q.703."
              },
    [ 141 ] = {
                linktype = "LINKTYPE_MTP3",
                dlt      = "DLT_MTP3",
                wtap     = "MTP3",
                comments = "Signaling System 7 Message Transfer Part Level 3, as"..
                           " specified by ITU-T Recommendation Q.704, with no MTP2"..
                           " header preceding the MTP3 packet."
              },
    [ 142 ] = {
                linktype = "LINKTYPE_SCCP",
                dlt      = "DLT_SCCP",
                wtap     = "SCCP",
                comments = "Signaling System 7 Signalling Connection Control Part"..
                           ", as specified by ITU-T Recommendation Q.711, ITU-T"..
                           " Recommendation Q.712, ITU-T Recommendation Q.713,"..
                           " and ITU-T Recommendation Q.714, with no MTP3 or MTP2"..
                           " headers preceding the SCCP packet."
              },
    [ 143 ] = {
                linktype = "LINKTYPE_DOCSIS",
                dlt      = "DLT_DOCSIS",
                wtap     = "DOCSIS",
                comments = "DOCSIS MAC frames, as described by the DOCSIS 3.0 MAC"..
                           " and Upper Layer Protocols Interface Specification."
              },
    [ 144 ] = {
                linktype = "LINKTYPE_LINUX_IRDA",
                dlt      = "DLT_LINUX_IRDA",
                wtap     = "IRDA",
                comments = "Linux-IrDA packets, with a LINKTYPE_LINUX_IRDA header"..
                           ", with the payload for IrDA frames beginning with by"..
                           " the IrLAP header as defined by IrDA Data Specifications,"..
                           " including the IrDA Link Access Protocol specification.",
                needphdr = true
              },
    [ 147 ] = {
                linktype = "LINKTYPE_USER0",
                dlt      = "DLT_USER0",
                wtap     = "USER0",
                comments = "Reserved for private use"
              },
    [ 148 ] = {
                linktype = "LINKTYPE_USER1",
                dlt      = "DLT_USER1",
                wtap     = "USER1",
                comments = "Reserved for private use"
              },
    [ 149 ] = {
                linktype = "LINKTYPE_USER2",
                dlt      = "DLT_USER2",
                wtap     = "USER2",
                comments = "Reserved for private use"
              },
    [ 150 ] = {
                linktype = "LINKTYPE_USER3",
                dlt      = "DLT_USER3",
                wtap     = "USER3",
                comments = "Reserved for private use"
              },
    [ 151 ] = {
                linktype = "LINKTYPE_USER4",
                dlt      = "DLT_USER4",
                wtap     = "USER4",
                comments = "Reserved for private use"
              },
    [ 152 ] = {
                linktype = "LINKTYPE_USER5",
                dlt      = "DLT_USER5",
                wtap     = "USER5",
                comments = "Reserved for private use"
              },
    [ 153 ] = {
                linktype = "LINKTYPE_USER6",
                dlt      = "DLT_USER6",
                wtap     = "USER6",
                comments = "Reserved for private use"
              },
    [ 154 ] = {
                linktype = "LINKTYPE_USER7",
                dlt      = "DLT_USER7",
                wtap     = "USER7",
                comments = "Reserved for private use"
              },
    [ 155 ] = {
                linktype = "LINKTYPE_USER8",
                dlt      = "DLT_USER8",
                wtap     = "USER8",
                comments = "Reserved for private use"
              },
    [ 156 ] = {
                linktype = "LINKTYPE_USER9",
                dlt      = "DLT_USER9",
                wtap     = "USER9",
                comments = "Reserved for private use"
              },
    [ 157 ] = {
                linktype = "LINKTYPE_USER10",
                dlt      = "DLT_USER10",
                wtap     = "USER10",
                comments = "Reserved for private use"
              },
    [ 158 ] = {
                linktype = "LINKTYPE_USER11",
                dlt      = "DLT_USER11",
                wtap     = "USER11",
                comments = "Reserved for private use"
              },
    [ 159 ] = {
                linktype = "LINKTYPE_USER12",
                dlt      = "DLT_USER12",
                wtap     = "USER12",
                comments = "Reserved for private use"
              },
    [ 160 ] = {
                linktype = "LINKTYPE_USER13",
                dlt      = "DLT_USER13",
                wtap     = "USER13",
                comments = "Reserved for private use"
              },
    [ 161 ] = {
                linktype = "LINKTYPE_USER14",
                dlt      = "DLT_USER14",
                wtap     = "USER14",
                comments = "Reserved for private use"
              },
    [ 162 ] = {
                linktype = "LINKTYPE_USER15",
                dlt      = "DLT_USER15",
                wtap     = "USER15",
                comments = "Reserved for private use"
              },
    [ 163 ] = {
                linktype = "LINKTYPE_IEEE802_11_AVS",
                dlt      = "DLT_IEEE802_11_RADIO_AVS",
                wtap     = "IEEE_802_11_AVS",
                comments = "AVS monitor mode information followed by an 802.11 header." 
              },
    [ 165 ] = {
                linktype = "LINKTYPE_BACNET_MS_TP",
                dlt      = "DLT_BACNET_MS_TP",
                wtap     = "BACNET_MS_TP",
                comments = "BACnet MS/TP frames, as specified by section 9.3 MS"..
                           "/TP Frame Format of ANSI/ASHRAE Standard 135, BACnet®"..
                           " - A Data Communication Protocol for Building Automation"..
                           " and Control Networks, including the preamble and,"..
                           " if present, the Data CRC."
              },
    [ 166 ] = {
                linktype = "LINKTYPE_PPP_PPPD",
                dlt      = "DLT_PPP_PPPD",
                wtap     = "UNKNOWN", -- not used by wireshark
                comments = "PPP in HDLC-like encapsulation, but with the 0xff address"..
                           " byte replaced by a direction indication - 0x00 for"..
                           " incoming and 0x01 for outgoing."
              },
    [ 167 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_PPPOE",
                comments = "Ethernet PPPoE frames captured on a service PIC."
              },
    [ 168 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "UNKNOWN", -- not used by wireshark
                comments = "Juniper private-chassis-internal meta-information."
              },
    [ 169 ] = {
                linktype = "LINKTYPE_GPRS_LLC",
                dlt      = "DLT_GPRS_LLC",
                wtap     = "GPRS_LLC",
                comments = "General Packet Radio Service Logical Link Control,"..
                           " as defined by 3GPP TS 04.64."
              },
    [ 172 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "GCOM_TIE1",
                comments = "Gcom, Inc., T1-E1 interface."
              },
    [ 173 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "GCOM_SERIAL",
                comments = "Gcom, Inc., serial interface."
              },
    [ 177 ] = {
                linktype = "LINKTYPE_LINUX_LAPD",
                dlt      = "DLT_LINUX_LAPD",
                wtap     = "LINUX_LAPD",
                comments = "Link Access Procedures on the D Channel (LAPD) frames"..
                           ", as specified by ITU-T Recommendation Q.920 and ITU-T"..
                           " Recommendation Q.921, captured via vISDN, with a "..
                           "LINKTYPE_LINUX_LAPD header, followed by the Q.921 frame,"..
                           " starting with the address field.",
                needphdr = true
              },
    [ 178 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_ETHER",
                comments = "Ethernet frames prepended with meta-information."
              },
    [ 179 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_PPP",
                comments = "PPP frames prepended with meta-information."
              },
    [ 180 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_FRELAY",
                comments = "Frame-Relay frames prepended with meta-information."
              },
    [ 181 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_CHDLC",
                comments = "C-HDLC frames prepended with meta-information."
              },
    [ 183 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "JUNIPER_VP",
                comments = "VoIP frames prepended with meta-information."
              },
    [ 186 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "USB",
                comments = "Raw USB packets."
              },
    [ 187 ] = {
                linktype = "LINKTYPE_BLUETOOTH_HCI_H4",
                dlt      = "DLT_BLUETOOTH_HCI_H4",
                wtap     = "BLUETOOTH_H4",
                comments = "Bluetooth HCI UART transport layer; the frame contains"..
                           " an HCI packet indicator byte, as specified by the"..
                           " UART Transport Layer portion of the most recent Bluetooth"..
                           " Core specification, followed by an HCI packet of the"..
                           " specified packet type, as specified by the Host Controller"..
                           " Interface Functional Specification portion of the"..
                           " most recent Bluetooth Core Specification."
              },
    [ 188 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "IEEE802_16_MAC_CPS",
                comments = "IEEE 802.16 MAC Common Part Sublayer."
              },
    [ 189 ] = {
                linktype = "LINKTYPE_USB_LINUX",
                dlt      = "DLT_USB_LINUX",
                wtap     = "USB_LINUX",
                comments = "USB packets, beginning with a Linux USB header, as"..
                           " specified by the struct usbmon_packet in the"..
                           " Documentation/usb/usbmon.txt file in the Linux"..
                           " source tree. Only the first 48 bytes of that header"..
                           " are present. All fields in the header are in the"..
                           " host byte order for the pcap file, as specified by"..
                           " the file's magic number, or for the section of the"..
                           " pcap-ng file, as specified by the Section Header Block."
              },
    [ 190 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "CAN20B",
                comments = "CAN 2.0b frame."
              },
    [ 192 ] = {
                linktype = "LINKTYPE_PPI",
                dlt      = "DLT_PPI",
                wtap     = "PPI",
                comments = "Per-Packet Information information, as specified by"..
                           " the Per-Packet Information Header Specification, followed"..
                           " by a packet with the LINKTYPE_ value specified by"..
                           " the pph_dlt field of that header."
              },
    [ 195 ] = {
                linktype = "LINKTYPE_IEEE802_15_4",
                dlt      = "DLT_IEEE802_15_4",
                wtap     = "IEEE802_15_4",
                comments = "IEEE 802.15.4 wireless Personal Area Network, with"..
                           " each packet having the FCS at the end of the frame."
              },
    [ 196 ] = {
                linktype = "LINKTYPE_SITA",
                dlt      = "DLT_SITA",
                wtap     = "SITA",
                comments = "Various link-layer types, with a pseudo-header, for SITA.",
                needphdr = true
              },
    [ 197 ] = {
                linktype = "LINKTYPE_ERF",
                dlt      = "DLT_ERF",
                wtap     = "ERF",
                comments = "Various link-layer types, with a pseudo-header, for"..
                           " Endace DAG cards; encapsulates Endace ERF records.",
                needphdr = true
              },
    [ 199 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "IPMB",
                comments = "ATCA-chassis Intelligent Platform Management Bus (IPMB)."
              },
    [ 201 ] = {
                linktype = "LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR",
                dlt      = "DLT_BLUETOOTH_HCI_H4_WITH_PHDR",
                wtap     = "BLUETOOTH_H4_WITH_PHDR",
                comments = "Bluetooth HCI UART transport layer; the frame contains"..
                           " a 4-byte direction field, in network byte order (big-endian),"..
                           " the low-order bit of which is set if the frame was"..
                           " sent from the host to the controller and clear if"..
                           " the frame was received by the host from the controller,"..
                           " followed by an HCI packet indicator byte, as specified"..
                           " by the UART Transport Layer portion of the most recent"..
                           " Bluetooth Core specification, followed by an HCI packet"..
                           " of the specified packet type, as specified by the"..
                           " Host Controller Interface Functional Specification"..
                           " portion of the most recent Bluetooth Core Specification.",
                needphdr = true
              },
    [ 202 ] = {
                linktype = "LINKTYPE_AX25_KISS",
                dlt      = "DLT_AX25_KISS",
                wtap     = "AX25_KISS",
                comments = "AX.25 packet, with a 1-byte KISS header containing"..
                           " a type indicator."
              },
    [ 203 ] = {
                linktype = "LINKTYPE_LAPD",
                dlt      = "DLT_LAPD",
                wtap     = "LAPD",
                comments = "Link Access Procedures on the D Channel (LAPD) frames"..
                           ", as specified by ITU-T Recommendation Q.920 and ITU-T"..
                           " Recommendation Q.921, starting with the address field,"..
                           " with no pseudo-header."
              },
    [ 204 ] = {
                linktype = "LINKTYPE_PPP_WITH_DIR",
                dlt      = "DLT_PPP_WITH_DIR",
                wtap     = "PPP_WITH_PHDR",
                comments = "PPP, as per RFC 1661 and RFC 1662, preceded with a"..
                           " one-byte pseudo-header with a zero value meaning 'received"..
                           " by this host' and a non-zero value meaning 'sent by this host'.",
                needphdr = true
              },
    [ 205 ] = {
                linktype = "LINKTYPE_C_HDLC_WITH_DIR",
                dlt      = "DLT_C_HDLC_WITH_DIR",
                wtap     = "UNKNOWN", -- not used by wireshark
                comments = "Cisco PPP with HDLC framing, as per section 4.3.1 of"..
                           " RFC 1547, preceded with a one-byte pseudo-header with"..
                           " a zero value meaning 'received by this host' and a"..
                           " non-zero value meaning 'sent by this host'."
              },
    [ 206 ] = {
                linktype = "LINKTYPE_FRELAY_WITH_DIR",
                dlt      = "DLT_FRELAY_WITH_DIR",
                wtap     = "UNKNOWN", -- not used by wireshark
                comments = "Frame Relay, preceded with a one-byte pseudo-header"..
                           " with a zero value meaning 'received by this host'"..
                           " and a non-zero value meaning 'sent by this host'."
              },
    [ 209 ] = {
                linktype = "LINKTYPE_IPMB_LINUX",
                dlt      = "DLT_IPMB_LINUX",
                wtap     = "I2C",
                comments = "IPMB over an I2C circuit, with a Linux-specific pseudo-header.",
                needphdr = true
              },
    [ 210 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "FLEXRAY",
                comments = "FlexRay frame."
              },
    [ 211 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "MOST",
                comments = "MOST frame."
              },
    [ 212 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "LIN",
                comments = "LIN frame."
              },
    [ 213 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "X2E_SERIAL",
                comments = "X2E Xoraya serial frame."
              },
    [ 214 ] = {
                linktype = "LINKTYPE_RESERVED",
                dlt      = "DLT_RESERVED",
                wtap     = "X2E_XORAYA",
                comments = "X2E Xoraya frame."
              },
    [ 215 ] = {
                linktype = "LINKTYPE_IEEE802_15_4_NONASK_PHY",
                dlt      = "DLT_IEEE802_15_4_NONASK_PHY",
                wtap     = "IEEE802_15_4_NONASK_PHY",
                comments = "IEEE 802.15.4 wireless Personal Area Network, with"..
                           " each packet having the FCS at the end of the frame,"..
                           " and with the PHY-level data for non-ASK PHYs (4 octets"..
                           " of 0 as preamble, one octet of SFD, one octet of frame"..
                           " length + reserved bit) preceding the MAC-layer data"..
                           " (starting with the frame control field)."
              },
    [ 220 ] = {
                linktype = "LINKTYPE_USB_LINUX_MMAPPED",
                dlt      = "DLT_USB_LINUX_MMAPPED",
                wtap     = "USB_LINUX_MMAPPED",
                comments = "USB packets, beginning with a Linux USB header, as"..
                           " specified by the struct usbmon_packet in the Documentation/usb/usbmon.txt"..
                           " file in the Linux source tree. All 64 bytes of the"..
                           " header are present. All fields in the header are in"..
                           " the host byte order for the pcap file, as specified"..
                           " by the file's magic number, or for the section of"..
                           " the pcap-ng file, as specified by the Section Header"..
                           " Block. For isochronous transfers, the ndesc field"..
                           " specifies the number of isochronous descriptors that follow."
              },
    [ 224 ] = {
                linktype = "LINKTYPE_FC_2",
                dlt      = "DLT_FC_2",
                wtap     = "FIBRE_CHANNEL_FC2",
                comments = "Fibre Channel FC-2 frames, beginning with a Frame_Header"..
                           "."
              },
    [ 225 ] = {
                linktype = "LINKTYPE_FC_2_WITH_FRAME_DELIMS",
                dlt      = "DLT_FC_2_WITH_FRAME_DELIMS",
                wtap     = "FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS",
                comments = "Fibre Channel FC-2 frames, beginning an encoding of"..
                           " the SOF, followed by a Frame_Header, and ending with"..
                           " an encoding of the SOF."
              },
    [ 226 ] = {
                linktype = "LINKTYPE_IPNET",
                dlt      = "DLT_IPNET",
                wtap     = "IPNET",
                comments = "Solaris ipnet pseudo-header, followed by an IPv4 or"..
                           " IPv6 datagram."
              },
    [ 227 ] = {
                linktype = "LINKTYPE_CAN_SOCKETCAN",
                dlt      = "DLT_CAN_SOCKETCAN",
                wtap     = "SOCKETCAN",
                comments = "CAN (Controller Area Network) frames, with a pseudo"..
                           "-header as supplied by Linux SocketCAN."
              },
    [ 228 ] = {
                linktype = "LINKTYPE_IPV4",
                dlt      = "DLT_IPV4",
                wtap     = "RAW_IP4",
                comments = "Raw IPv4; the packet begins with an IPv4 header." 
              },
    [ 229 ] = {
                linktype = "LINKTYPE_IPV6",
                dlt      = "DLT_IPV6",
                wtap     = "RAW_IP6",
                comments = "Raw IPv6; the packet begins with an IPv6 header." 
              },
    [ 230 ] = {
                linktype = "LINKTYPE_IEEE802_15_4_NOFCS",
                dlt      = "DLT_IEEE802_15_4_NOFCS",
                wtap     = "IEEE802_15_4_NOFCS",
                comments = "IEEE 802.15.4 wireless Personal Area Network, without"..
                           " the FCS at the end of the frame."
              },
    [ 231 ] = {
                linktype = "LINKTYPE_DBUS",
                dlt      = "DLT_DBUS",
                wtap     = "DBUS",
                comments = "Raw D-Bus messages, starting with the endianness flag"..
                           ", followed by the message type, etc., but without the"..
                           " authentication handshake before the message sequence."
              },
    [ 235 ] = {
                linktype = "LINKTYPE_DVB_CI",
                dlt      = "DLT_DVB_CI",
                wtap     = "DVBCI",
                comments = "DVB-CI (DVB Common Interface for communication between"..
                           " a PC Card module and a DVB receiver), with the message"..
                           " format specified by the PCAP format for DVB-CI specification."
              },
    [ 236 ] = {
                linktype = "LINKTYPE_MUX27010",
                dlt      = "DLT_MUX27010",
                wtap     = "MUX27010",
                comments = "Variant of 3GPP TS 27.010 multiplexing protocol (similar"..
                           " to, but not the same as, 27.010)."
              },
    [ 237 ] = {
                linktype = "LINKTYPE_STANAG_5066_D_PDU",
                dlt      = "DLT_STANAG_5066_D_PDU",
                wtap     = "STANAG_5066_D_PDU",
                comments = "D_PDUs as described by NATO standard STANAG 5066, starting"..
                           " with the synchronization sequence, and including both"..
                           " header and data CRCs. The current version of STANAG"..
                           " 5066 is backwards-compatible with the 1.0.2 version,"..
                           " although newer versions are classified."
              },
    [ 239 ] = {
                linktype = "LINKTYPE_NFLOG",
                dlt      = "DLT_NFLOG",
                wtap     = "NFLOG",
                comments = "Linux netlink NETLINK NFLOG socket log messages."
              },
    [ 240 ] = {
                linktype = "LINKTYPE_NETANALYZER",
                dlt      = "DLT_NETANALYZER",
                wtap     = "NETANALYZER",
                comments = "Pseudo-header for Hilscher Gesellschaft für Systemautomation"..
                           " mbH netANALYZER devices, followed by an Ethernet frame,"..
                           " beginning with the MAC header and ending with the FCS."
              },
    [ 241 ] = {
                linktype = "LINKTYPE_NETANALYZER_TRANSPARENT",
                dlt      = "DLT_NETANALYZER_TRANSPARENT",
                wtap     = "NETANALYZER_TRANSPARENT",
                comments = "Pseudo-header for Hilscher Gesellschaft für Systemautomation"..
                           " mbH netANALYZER devices, followed by an Ethernet frame,"..
                           " beginning with the preamble, SFD, and MAC header,"..
                           " and ending with the FCS."
              },
    [ 242 ] = {
                linktype = "LINKTYPE_IPOIB",
                dlt      = "DLT_IPOIB",
                wtap     = "IP_OVER_IB",
                comments = "IP-over-InfiniBand, as specified by RFC 4391 section"..
                           " 6."
              },
    [ 243 ] = {
                linktype = "LINKTYPE_MPEG_2_TS",
                dlt      = "DLT_MPEG_2_TS",
                wtap     = "MPEG_2_TS",
                comments = "MPEG-2 Transport Stream transport packets, as specified"..
                           " by ISO 13818-1/ITU-T Recommendation H.222.0 (see table"..
                           " 2-2 of section 2.4.3.2 'Transport Stream packet layer')."
              },
    [ 244 ] = {
                linktype = "LINKTYPE_NG40",
                dlt      = "DLT_NG40",
                wtap     = "UNKNOWN", -- not used by wireshark
                comments = "Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM"..
                           " and Iub/Iur-over-IP format as used by their ng40 protocol"..
                           " tester, followed by frames for the Frame Protocol"..
                           " as specified by 3GPP TS 25.427 for dedicated channels"..
                           " and 3GPP TS 25.435 for common/shared channels in the"..
                           " case of ATM AAL2 or UDP traffic, by SSCOP packets"..
                           " as specified by ITU-T Recommendation Q.2110 for ATM"..
                           " AAL5 traffic, and by NBAP packets for SCTP traffic."
              },
    [ 245 ] = {
                linktype = "LINKTYPE_NFC_LLCP",
                dlt      = "DLT_NFC_LLCP",
                wtap     = "NFC_LLCP",
                comments = "Pseudo-header for NFC LLCP packet captures, followed"..
                           " by frame data for the LLCP Protocol as specified by"..
                           " NFCForum-TS-LLCP_1.1."
              },
    [ 247 ] = {
                linktype = "LINKTYPE_INFINIBAND",
                dlt      = "DLT_INFINIBAND",
                wtap     = "UNKNOWN", -- not used by wireshark
                comments = "Raw InfiniBand frames, starting with the Local Routing"..
                           " Header, as specified in Chapter 5 'Data packet format'"..
                           " of InfiniBand™ Architectural Specification Release"..
                           " 1.2.1 Volume 1 - General Specifications."
              },
    [ 248 ] = {
                linktype = "LINKTYPE_SCTP",
                dlt      = "DLT_SCTP",
                wtap     = "SCTP",
                comments = "SCTP packets, as defined by RFC 4960, with no lower"..
                           "-level protocols such as IPv4 or IPv6."
              },
    [ 249 ] = {
                linktype = "LINKTYPE_USBPCAP",
                dlt      = "DLT_USBPCAP",
                wtap     = "USBPCAP",
                comments = "USB packets, beginning with a USBPcap header."
              },
    [ 250 ] = {
                linktype = "LINKTYPE_RTAC_SERIAL",
                dlt      = "DLT_RTAC_SERIAL",
                wtap     = "RTAC_SERIAL",
                comments = "Serial-line packet header for the Schweitzer Engineering"..
                           " Laboratories 'RTAC' product, followed by a payload"..
                           " for one of a number of industrial control protocols."
              },
    [ 251 ] = {
                linktype = "LINKTYPE_BLUETOOTH_LE_LL",
                dlt      = "DLT_BLUETOOTH_LE_LL",
                wtap     = "BLUETOOTH_LE_LL",
                comments = "Bluetooth Low Energy air interface Link Layer packets"..
                           ", in the format described in section 2.1 'PACKET FORMAT'"..
                           " of volume 6 of the Bluetooth Specification Version"..
                           " 4.0 (see PDF page 2200), but without the Preamble."
              },
    [ 253 ] = {
                linktype = "LINKTYPE_NETLINK",
                dlt      = "DLT_NETLINK",
                wtap     = "NETLINK",
                comments = "Linux Netlink capture encapsulation."
              },
    [ 254 ] = {
                linktype = "LINKTYPE_BLUETOOTH_LINUX_MONITOR",
                dlt      = "DLT_BLUETOOTH_LINUX_MONITOR",
                wtap     = "BLUETOOTH_LINUX_MONITOR",
                comments = "Bluetooth Linux Monitor encapsulation of traffic for"..
                           " the BlueZ stack.",
                needphdr = true
              },
    [ 255 ] = {
                linktype = "LINKTYPE_BLUETOOTH_BREDR_BB",
                dlt      = "DLT_BLUETOOTH_BREDR_BB",
                wtap     = "BLUETOOTH_BREDR_BB",
                comments = "Bluetooth Basic Rate and Enhanced Data Rate baseband"..
                           " packets."
              },
    [ 256 ] = {
                linktype = "LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR",
                dlt      = "DLT_BLUETOOTH_LE_LL_WITH_PHDR",
                wtap     = "BLUETOOTH_LE_LL_WITH_PHDR",
                comments = "Bluetooth Low Energy link-layer packets."
              },
    [ 257 ] = {
                linktype = "LINKTYPE_PROFIBUS_DL",
                dlt      = "DLT_PROFIBUS_DL",
                wtap     = "UNKNOWN", -- not used by wireshark
                comments = "PROFIBUS data link layer packets, as specified by IEC"..
                           " standard 61158-6-3, beginning with the start delimiter,"..
                           " ending with the end delimiter, and including all octets"..
                           " between them. "
              },
}

-- wtap names aren't always the linktype name suffix, so we need to
-- sanity check the above table isn't bogus (ie, that I didn't screw up)
for k,t in pairs(linktype.info) do
    if not wtap_encaps[t.wtap] then
        error("linktype_info table entry #" .. k .. " has invalid wtap: " .. t.wtap)
    end
end

-- build a linktype value-string table from the linktype_info table
linktype.valstr = {}
for k,t in pairs(linktype.info) do
    linktype.valstr[k] = t.linktype
end

-- build a dlt value-string table from the linktype_info table
linktype.dlt = { valstr = {} }
for k,t in pairs(linktype.info) do
    linktype.dlt.valstr[k] = t.dlt
end

-- build a wtap value-string table from the linktype_info table
linktype.wtap = { valstr = {} }
for k,t in pairs(linktype.info) do
    linktype.wtap.valstr[k] = t.wtap
end

return linktype
