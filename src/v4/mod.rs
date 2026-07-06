//! # DHCPv4
//!
//! This module provides types and utility functions for encoding/decoding a DHCPv4 message.
//!
//! ## Example - constructing messages
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use usg_dhcproto::{v4, Encodable, Encoder};
//! // arbitrary hardware addr
//! let chaddr = vec![
//!     29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
//! ];
//! // construct a new Message
//! let mut msg = v4::Message::default();
//! msg.set_flags(v4::Flags::default().set_broadcast()) // set broadcast to true
//!     .set_chaddr(&chaddr) // set chaddr
//!     .opts_mut()
//!     .insert(v4::DhcpOption::MessageType(v4::MessageType::Discover)); // set msg type
//!
//! // set some more options
//! msg.opts_mut()
//!     .insert(v4::DhcpOption::ParameterRequestList(vec![
//!         v4::OptionCode::SubnetMask,
//!         v4::OptionCode::Router,
//!         v4::OptionCode::DomainNameServer,
//!         v4::OptionCode::DomainName,
//!     ]));
//! msg.opts_mut()
//!     .insert(v4::DhcpOption::ClientIdentifier(chaddr));
//!
//! // now encode to bytes
//! let mut buf = Vec::new();
//! let mut e = Encoder::new(&mut buf);
//! msg.encode(&mut e)?;
//!
//! // buf now has the contents of the encoded DHCP message
//! # Ok(()) }
//! ```
//!
//! ## Example - decoding messages
//!
//! ```rust
//! #  fn bootreq() -> Vec<u8> {
//! #        vec![
//! #            1u8, // op
//! #            2,   // htype
//! #            3,   // hlen
//! #            4,   // ops
//! #            5, 6, 7, 8, // xid
//! #            9, 10, // secs
//! #            11, 12, // flags
//! #            13, 14, 15, 16, // ciaddr
//! #            17, 18, 19, 20, // yiaddr
//! #            21, 22, 23, 24, // siaddr
//! #            25, 26, 27, 28, // giaddr
//! #            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, // chaddr
//! #            45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
//! #            67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
//! #            89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
//! #            0, // sname: "-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk",
//! #            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
//! #            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
//! #            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
//! #            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
//! #            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
//! #            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
//! #            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
//! #            109, 0, 0, 0, 0, 0, 0, 0,
//! #            0, // file: "mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}m",
//! #            99, 130, 83, 99, // magic cookie
//! #        ]
//! #    }
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use usg_dhcproto::{v4::Message, Decoder, Decodable};
//! let offer = bootreq();
//! let msg = Message::decode(&mut Decoder::new(&offer))?;
//! # Ok(()) }
//! ```
//!
use core::{fmt, net::Ipv4Addr, str::Utf8Error};

use alloc::{string::String, vec::Vec};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod bulk_query;
mod flags;
pub mod fqdn;
mod htype;
mod opcode;
mod options;

pub mod borrowed;
pub mod relay;

// re-export submodules from proto::msg
pub use self::{flags::*, htype::*, opcode::*, options::*};
use crate::decoder::trim_nul;
pub use crate::{
    decoder::{Decodable, Decoder},
    encoder::{Encodable, Encoder},
    error::*,
};

pub const MAGIC: [u8; 4] = [99, 130, 83, 99];
pub const MIN_PACKET_SIZE: usize = 300;

/// default dhcpv4 server port
pub const SERVER_PORT: u16 = 67;
/// default dhcpv4 client port
pub const CLIENT_PORT: u16 = 68;

/// [Dynamic Host Configuration Protocol](https://tools.ietf.org/html/rfc2131#section-2)
///
///```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
/// +---------------+---------------+---------------+---------------+
/// |                            xid (4)                            |
/// +-------------------------------+-------------------------------+
/// |           secs (2)            |           flags (2)           |
/// +-------------------------------+-------------------------------+
/// |                          ciaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          yiaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          siaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          giaddr  (4)                          |
/// +---------------------------------------------------------------+
/// |                          chaddr  (16)                         |
/// +---------------------------------------------------------------+
/// |                          sname   (64)                         |
/// +---------------------------------------------------------------+
/// |                          file    (128)                        |
/// +---------------------------------------------------------------+
/// |                          options (variable)                   |
/// +---------------------------------------------------------------+
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// op code / message type
    opcode: Opcode,
    /// Hardware address type: <https://tools.ietf.org/html/rfc3232>
    htype: HType,
    /// Hardware address length
    hlen: u8,
    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    hops: u8,
    /// Transaction ID, a random number chosen by the client
    xid: u32,
    /// seconds elapsed since client began address acquisition or renewal process
    secs: u16,
    /// Flags
    flags: Flags,
    /// Client IP
    ciaddr: Ipv4Addr,
    /// Your IP
    yiaddr: Ipv4Addr,
    /// Server IP
    siaddr: Ipv4Addr,
    /// Gateway IP
    giaddr: Ipv4Addr,
    /// Client hardware address
    chaddr: [u8; 16],
    /// Server hostname
    sname: Option<Vec<u8>>,
    // File name
    fname: Option<Vec<u8>>,
    magic: [u8; 4],
    opts: DhcpOptions,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            opcode: Opcode::BootRequest,
            htype: HType::Eth,
            hlen: 0,
            hops: 0,
            xid: rand::random(),
            secs: 0,
            flags: Flags::default(),
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 16],
            sname: None,
            fname: None,
            magic: MAGIC,
            opts: DhcpOptions::default(),
        }
    }
}

impl Message {
    /// returns a new Message with OpCode set to BootRequest and a new random id
    /// # Panic
    ///   panics if chaddr is greater len than 16
    pub fn new(
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        giaddr: Ipv4Addr,
        chaddr: &[u8],
    ) -> Self {
        Self::new_with_id(rand::random(), ciaddr, yiaddr, siaddr, giaddr, chaddr)
    }

    /// returns a new Message with OpCode set to BootRequest
    /// # Panic
    ///   panics if chaddr is greater len than 16
    pub fn new_with_id(
        xid: u32,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        giaddr: Ipv4Addr,
        chaddr: &[u8],
    ) -> Self {
        assert!(chaddr.len() <= 16);

        // copy our chaddr into static array
        let mut new_chaddr = [0; 16];
        let len = chaddr.len();
        new_chaddr[..len].copy_from_slice(chaddr);

        Self {
            hlen: len as u8,
            xid,
            flags: Flags::default(),
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr: new_chaddr,
            ..Self::default()
        }
    }

    /// Get the message's opcode.
    /// op code / message type
    pub fn opcode(&self) -> Opcode {
        self.opcode
    }

    /// Set the message's opcode.
    /// op code / message type
    pub fn set_opcode(&mut self, opcode: Opcode) -> &mut Self {
        self.opcode = opcode;
        self
    }

    /// Get the message's hardware type.
    pub fn htype(&self) -> HType {
        self.htype
    }

    /// Set the message's hardware type.
    pub fn set_htype(&mut self, htype: HType) -> &mut Self {
        self.htype = htype;
        self
    }

    /// Get the message's hardware len (len of chaddr).
    pub fn hlen(&self) -> u8 {
        self.hlen
    }

    /// Get the message's hops.
    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    pub fn hops(&self) -> u8 {
        self.hops
    }

    /// Set the message's hops.
    /// Client sets to zero, optionally used by relay agents when booting via a relay agent.
    pub fn set_hops(&mut self, hops: u8) -> &mut Self {
        self.hops = hops;
        self
    }

    /// Get the message's chaddr.
    pub fn chaddr(&self) -> &[u8] {
        &self.chaddr[..(self.hlen as usize)]
    }

    /// Set the message's chaddr. `chaddr` can only up to 16 bytes in length
    pub fn set_chaddr(&mut self, chaddr: &[u8]) -> &mut Self {
        let mut new_chaddr = [0; 16];
        self.hlen = chaddr.len() as u8;
        if chaddr.len() >= 16 {
            new_chaddr.copy_from_slice(&chaddr[..16]);
            self.hlen = 16
        } else {
            new_chaddr[..chaddr.len()].copy_from_slice(chaddr);
        }
        self.chaddr = new_chaddr;
        self
    }

    /// Get the message's giaddr.
    /// Gateway IP
    pub fn giaddr(&self) -> Ipv4Addr {
        self.giaddr
    }
    /// Set the message's giaddr.
    /// Gateway IP
    pub fn set_giaddr<I: Into<Ipv4Addr>>(&mut self, giaddr: I) -> &mut Self {
        self.giaddr = giaddr.into();
        self
    }

    /// Get the message's siaddr.
    /// Server IP
    pub fn siaddr(&self) -> Ipv4Addr {
        self.siaddr
    }
    /// Set the message's siaddr.
    /// Server IP
    pub fn set_siaddr<I: Into<Ipv4Addr>>(&mut self, siaddr: I) -> &mut Self {
        self.siaddr = siaddr.into();
        self
    }

    /// Get the message's yiaddr.
    /// Your IP
    /// In an OFFER this is the ip the server is offering
    pub fn yiaddr(&self) -> Ipv4Addr {
        self.yiaddr
    }

    /// Set the message's siaddr.
    /// Your IP
    pub fn set_yiaddr<I: Into<Ipv4Addr>>(&mut self, yiaddr: I) -> &mut Self {
        self.yiaddr = yiaddr.into();
        self
    }

    /// Get the message's ciaddr.
    /// Client IP
    pub fn ciaddr(&self) -> Ipv4Addr {
        self.ciaddr
    }

    /// Set the message's siaddr.
    /// Client IP
    pub fn set_ciaddr<I: Into<Ipv4Addr>>(&mut self, ciaddr: I) -> &mut Self {
        self.ciaddr = ciaddr.into();
        self
    }

    /// clear addrs
    pub fn clear_addrs(&mut self) -> &mut Self {
        self.ciaddr = Ipv4Addr::UNSPECIFIED;
        self.yiaddr = Ipv4Addr::UNSPECIFIED;
        self.siaddr = Ipv4Addr::UNSPECIFIED;
        self.giaddr = Ipv4Addr::UNSPECIFIED;
        self
    }

    /// Get the message's flags.
    pub fn flags(&self) -> Flags {
        self.flags
    }

    /// Set the message's flags.
    pub fn set_flags(&mut self, flags: Flags) -> &mut Self {
        self.flags = flags;
        self
    }

    /// Get the message's secs.
    pub fn secs(&self) -> u16 {
        self.secs
    }
    /// Set the message's secs.
    pub fn set_secs(&mut self, secs: u16) -> &mut Self {
        self.secs = secs;
        self
    }
    /// Get the message's xid.
    /// Transaction ID, a random number chosen by the client
    pub fn xid(&self) -> u32 {
        self.xid
    }
    /// Set the message's xid.
    /// Transaction ID, a random number chosen by the client
    pub fn set_xid(&mut self, xid: u32) -> &mut Self {
        self.xid = xid;
        self
    }
    /// Get a reference to the message's fname. No particular encoding is enforced.
    pub fn fname(&self) -> Option<&[u8]> {
        self.fname.as_deref()
    }
    /// Clear the `fname` header field.
    pub fn clear_fname(&mut self) {
        self.fname = None;
    }
    /// Get a reference to the message's fname, UTF-8 encoded
    pub fn fname_str(&self) -> Option<Result<&str, Utf8Error>> {
        self.fname().map(core::str::from_utf8)
    }
    /// Set the message's fname using a UTF-8 string
    /// # Panic
    /// panics if file is greater than 128 bytes long
    pub fn set_fname_str<S: AsRef<str>>(&mut self, file: S) -> &mut Self {
        let file = file.as_ref().as_bytes();
        assert!(file.len() <= 128);
        self.fname = Some(file.to_vec());
        self
    }
    /// Set the message's fname. No particular encoding is enforced.
    /// # Panic
    /// panics if file is greater than 128 bytes long
    pub fn set_fname(&mut self, file: &[u8]) -> &mut Self {
        assert!(file.len() <= 128);
        self.fname = Some(file.to_vec());
        self
    }
    /// Get a reference to the message's sname. No particular encoding is enforced.
    pub fn sname(&self) -> Option<&[u8]> {
        self.sname.as_deref()
    }
    /// Clear the `sname` header field.
    pub fn clear_sname(&mut self) {
        self.sname = None;
    }
    /// Get a reference to the message's sname as a UTF-8 encoded string.
    pub fn sname_str(&self) -> Option<Result<&str, Utf8Error>> {
        self.sname().map(core::str::from_utf8)
    }
    /// Set the message's sname. No particular encoding is enforced.
    /// # Panic
    /// panics will if sname is greater than 64 bytes long
    pub fn set_sname(&mut self, sname: &[u8]) -> &mut Self {
        assert!(sname.len() <= 64);
        self.sname = Some(sname.to_vec());
        self
    }
    /// Set the message's sname using a UTF-8 string
    /// # Panic
    /// panics will if sname is greater than 64 bytes long
    pub fn set_sname_str<S: AsRef<str>>(&mut self, sname: S) -> &mut Self {
        let sname = sname.as_ref().as_bytes();
        assert!(sname.len() <= 64);
        self.sname = Some(sname.to_vec());
        self
    }
    /// Get a reference to the message's opts.
    pub fn opts(&self) -> &DhcpOptions {
        &self.opts
    }

    /// Set the DHCP options
    pub fn set_opts(&mut self, opts: DhcpOptions) -> &mut Self {
        self.opts = opts;
        self
    }

    /// Get a mutable reference to the message's options.
    pub fn opts_mut(&mut self) -> &mut DhcpOptions {
        &mut self.opts
    }
}

/// Copy the option TLVs at the start of `field` into `combined`, up to the
/// first `End` marker. `Pad` bytes and the `OptionOverload` (52) marker are
/// dropped so that the fragments of an option split across a region boundary
/// (RFC 3396) are left adjacent and get concatenated when decoded. Stops early
/// on a truncated option so it never reads out of bounds.
fn append_region_options(combined: &mut Vec<u8>, field: &[u8]) {
    let mut i = 0;
    while i < field.len() {
        match field[i] {
            255 => break, // End
            0 => i += 1,  // Pad - dropped
            code => {
                let Some(&len) = field.get(i + 1) else { break };
                let end = i + 2 + len as usize;
                if end > field.len() {
                    break; // truncated option
                }
                if code != u8::from(OptionCode::OptionOverload) {
                    combined.extend_from_slice(&field[i..end]);
                }
                i = end;
            }
        }
    }
}

impl Decodable for Message {
    fn decode(decoder: &mut Decoder<'_>) -> DecodeResult<Self> {
        let opcode = Opcode::decode(decoder)?;
        let htype = decoder.read_u8()?.into();
        let hlen = decoder.read_u8()?;
        let hops = decoder.read_u8()?;
        let xid = decoder.read_u32()?;
        let secs = decoder.read_u16()?;
        let flags = decoder.read_u16()?.into();
        let ciaddr = decoder.read_u32()?.into();
        let yiaddr = decoder.read_u32()?.into();
        let siaddr = decoder.read_u32()?.into();
        let giaddr = decoder.read_u32()?.into();
        let chaddr = decoder.read::<16>()?;
        // Keep the raw fixed-length fields around: whether they hold a
        // hostname/bootfile or an overloaded option block isn't known until the
        // options field has been parsed for option 52.
        let sname_raw = decoder.read::<64>()?;
        let file_raw = decoder.read::<128>()?;
        // The magic cookie (RFC 2131) marks the start of the options field; a
        // mismatch means this isn't a conformant DHCP message and the trailing
        // bytes can't be trusted as options.
        let magic = decoder.read::<4>()?;
        if magic != MAGIC {
            return Err(DecodeError::InvalidData(
                u32::from_be_bytes(magic),
                "invalid DHCP magic cookie",
            ));
        }
        // The remaining bytes are the main options field; capture them so an
        // overloaded field's options can be reassembled with them (RFC 3396).
        let opts_raw = decoder.buffer();
        let mut opts = DhcpOptions::decode(decoder)?;

        // Option Overload - RFC 2131 §4.1 / RFC 2132 §9.3
        // value 1: `file` field holds options, 2: `sname` field holds options,
        // 3: both. The option MUST appear in the main options field.
        let overload = match opts.get(OptionCode::OptionOverload) {
            Some(DhcpOption::OptionOverload(v)) => *v,
            _ => 0,
        };
        if overload != 0 {
            // Splice the option streams of every active region into one buffer
            // and decode it in a single pass, so an option split across a region
            // boundary (RFC 3396) is reassembled rather than dropped. Pad and the
            // option-52 marker are dropped while splicing so split fragments stay
            // adjacent (and the marker doesn't survive into the flattened map).
            // Region order: options -> file -> sname.
            let mut combined = Vec::with_capacity(opts_raw.len() + 192);
            append_region_options(&mut combined, opts_raw);
            if overload & 0b01 != 0 {
                append_region_options(&mut combined, &file_raw);
            }
            if overload & 0b10 != 0 {
                append_region_options(&mut combined, &sname_raw);
            }
            combined.push(255); // End
            opts = DhcpOptions::decode(&mut Decoder::new(&combined))?;
        }

        // An overloaded field carries options, not a name.
        let sname = if overload & 0b10 != 0 {
            None
        } else {
            trim_nul(&sname_raw)
        };
        let fname = if overload & 0b01 != 0 {
            None
        } else {
            trim_nul(&file_raw)
        };

        Ok(Message {
            opcode,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            fname,
            magic,
            opts,
        })
    }
}

impl Encodable for Message {
    fn encode(&self, e: &mut Encoder<'_>) -> EncodeResult<()> {
        self.opcode.encode(e)?;
        self.htype.encode(e)?;
        e.write_u8(self.hlen)?;
        e.write_u8(self.hops)?;
        e.write_u32(self.xid)?;
        e.write_u16(self.secs)?;
        e.write_u16(self.flags.into())?;
        e.write_u32(self.ciaddr.into())?;
        e.write_u32(self.yiaddr.into())?;
        e.write_u32(self.siaddr.into())?;
        e.write_u32(self.giaddr.into())?;
        e.write_slice(&self.chaddr[..])?;
        e.write_fill(&self.sname, 64)?;
        e.write_fill(&self.fname, 128)?;

        e.write(self.magic)?;
        self.opts.encode(e)?;
        Ok(())
    }
}

impl Message {
    /// Encode the message, spilling options that do not fit within `max_len`
    /// bytes into the `file` then `sname` header fields (RFC 2131 §4.1 / RFC
    /// 2132 §9.3 "option overload"). The option-52 marker is inserted
    /// automatically, and an overloaded field's name value is not written.
    ///
    /// If all options fit within `max_len` this behaves like
    /// [`encode`](Encodable::encode) (no overload; the name fields are written
    /// as usual). Returns [`EncodeError::MessageTooLarge`] if the options do not
    /// fit even after using both header fields. Each option is placed whole into
    /// a single region, so a single option larger than a field cannot spill into
    /// it.
    pub fn encode_overloaded(&self, e: &mut Encoder<'_>, max_len: usize) -> EncodeResult<()> {
        // Encode each option to its own byte block, preserving order and
        // skipping any pre-existing overload marker (we set our own).
        let mut main = Vec::new();
        let mut file = Vec::new();
        let mut sname = Vec::new();
        // Leave room for a terminating End in each field, and for the 3-byte
        // option-52 marker at the start of the main options field.
        const FILE_CAP: usize = 128 - 1;
        const SNAME_CAP: usize = 64 - 1;
        let main_cap = max_len.saturating_sub(240 + 1 + 3);

        for (code, opt) in self.opts.iter() {
            if *code == OptionCode::OptionOverload {
                continue;
            }
            let mut block = Vec::new();
            opt.encode(&mut Encoder::new(&mut block))?;
            if main.len() + block.len() <= main_cap {
                main.extend_from_slice(&block);
            } else if file.len() + block.len() <= FILE_CAP {
                file.extend_from_slice(&block);
            } else if sname.len() + block.len() <= SNAME_CAP {
                sname.extend_from_slice(&block);
            } else {
                return Err(EncodeError::MessageTooLarge { max_len });
            }
        }

        // Nothing spilled -> a normal encode is correct and simpler.
        if file.is_empty() && sname.is_empty() {
            return self.encode(e);
        }

        let overload = u8::from(!file.is_empty()) | (u8::from(!sname.is_empty()) << 1);

        // header up to chaddr (offset 0..44)
        self.opcode.encode(e)?;
        self.htype.encode(e)?;
        e.write_u8(self.hlen)?;
        e.write_u8(self.hops)?;
        e.write_u32(self.xid)?;
        e.write_u16(self.secs)?;
        e.write_u16(self.flags.into())?;
        e.write_u32(self.ciaddr.into())?;
        e.write_u32(self.yiaddr.into())?;
        e.write_u32(self.siaddr.into())?;
        e.write_u32(self.giaddr.into())?;
        e.write_slice(&self.chaddr[..])?;

        // sname field (44..108) comes before file on the wire
        if sname.is_empty() {
            e.write_fill(&self.sname, 64)?;
        } else {
            sname.push(255); // End
            e.write_fill_bytes(&sname, 64)?;
        }
        // file field (108..236)
        if file.is_empty() {
            e.write_fill(&self.fname, 128)?;
        } else {
            file.push(255); // End
            e.write_fill_bytes(&file, 128)?;
        }
        e.write(self.magic)?;

        // main options field: the overload marker, the packed options, then End
        e.write_u8(OptionCode::OptionOverload.into())?;
        e.write_u8(1)?;
        e.write_u8(overload)?;
        e.write_slice(&main)?;
        e.write_u8(255)?; // End
        Ok(())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("xid", &self.xid())
            .field("broadcast_flag", &self.flags().broadcast())
            .field("ciaddr", &self.ciaddr())
            .field("yiaddr", &self.yiaddr())
            .field("siaddr", &self.siaddr())
            .field("giaddr", &self.giaddr())
            .field(
                "chaddr",
                &bytes_to_hex(self.chaddr())
                    .chars()
                    .enumerate()
                    .flat_map(|(i, c)| {
                        if i != 0 && i % 2 == 0 {
                            Some(':')
                        } else {
                            None
                        }
                        .into_iter()
                        .chain(core::iter::once(c))
                    })
                    .collect::<String>(),
            )
            .field(
                "opts",
                &self.opts().iter().map(|(_, v)| v).collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut ret = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        ret.push_str(&alloc::format!("{:02x}", b));
    }
    ret
}

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;

    use super::*;

    type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

    fn decode_ipv4(input: Vec<u8>, expected: MessageType) -> Result<()> {
        // decode
        let msg = Message::decode(&mut Decoder::new(&input))?;
        dbg!(&msg);
        assert_eq!(msg.opts().msg_type().unwrap(), expected);
        // now encode
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        println!("{buf:?}");
        println!("{input:?}");
        // decode again
        let res = Message::decode(&mut Decoder::new(&buf))?;
        // check Messages are equal after decoding/encoding
        assert_eq!(msg, res);
        Ok(())
    }

    #[test]
    fn test_hex() {
        let data: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let hex = bytes_to_hex(data);
        assert_eq!(&hex, "deadbeef");
    }
    #[test]
    fn decode_offer() -> Result<()> {
        decode_ipv4(offer(), MessageType::Offer)?;
        Ok(())
    }

    #[test]
    fn decode_discover() -> Result<()> {
        decode_ipv4(discover(), MessageType::Discover)?;
        Ok(())
    }

    #[test]
    fn decode_offer_two() -> Result<()> {
        decode_ipv4(other_offer(), MessageType::Offer)?;
        Ok(())
    }

    #[test]
    fn decode_bootreq() -> Result<()> {
        let offer = bootreq();
        let msg = Message::decode(&mut Decoder::new(&offer))?;
        println!("{msg:?}");
        // now encode
        let mut buf = Vec::new();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        assert_eq!(buf, bootreq());
        Ok(())
    }

    #[test]
    fn decode_full_sname_no_nul_preserved() -> Result<()> {
        // a `sname` field that is completely filled (no NUL terminator) must be
        // preserved rather than dropped.
        let mut bytes = offer();
        for b in &mut bytes[44..108] {
            *b = b'x';
        }
        let msg = Message::decode(&mut Decoder::new(&bytes))?;
        assert_eq!(msg.sname(), Some(&[b'x'; 64][..]));
        Ok(())
    }

    #[test]
    fn decode_rejects_bad_magic() {
        // a packet whose magic cookie isn't 99.130.83.99 is not a valid DHCP
        // message and must be rejected rather than silently mis-parsed.
        let mut bytes = offer();
        assert_eq!(bytes[236], 0x63); // sanity: cookie starts here
        bytes[236] = 0x00; // corrupt it
        assert!(Message::decode(&mut Decoder::new(&bytes)).is_err());
    }

    #[test]
    fn encode_overloaded_round_trips() -> Result<()> {
        let mut msg = Message::default();
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::Offer));
        opts.insert(DhcpOption::Hostname(
            b"a-fairly-long-client-hostname".to_vec(),
        ));
        opts.insert(DhcpOption::DomainName(
            b"dept.example.internal.test".to_vec(),
        ));
        opts.insert(DhcpOption::Message(
            b"a somewhat lengthy status text here".to_vec(),
        ));
        opts.insert(DhcpOption::BootfileName(
            b"/boot/images/pxelinux.0".to_vec(),
        ));

        // a small cap forces options to spill into the file/sname fields
        let mut buf = Vec::new();
        msg.encode_overloaded(&mut Encoder::new(&mut buf), 300)?;
        assert!(buf.len() <= 300);

        let decoded = Message::decode(&mut Decoder::new(&buf))?;
        for (code, opt) in msg.opts().iter() {
            assert_eq!(decoded.opts().get(*code), Some(opt), "lost option {code:?}");
        }
        Ok(())
    }

    #[test]
    fn encode_overloaded_no_spill_matches_encode() -> Result<()> {
        // when everything fits, encode_overloaded == encode (no option 52)
        let mut msg = Message::default();
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));

        let mut a = Vec::new();
        msg.encode(&mut Encoder::new(&mut a))?;
        let mut b = Vec::new();
        msg.encode_overloaded(&mut Encoder::new(&mut b), 576)?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn test_set_chaddr() -> Result<()> {
        let mut msg = Message::new(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        );
        msg.set_chaddr(&[0, 1, 2, 3, 4, 5]);
        assert_eq!(msg.chaddr().len(), 6);

        msg.set_chaddr(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
        ]);
        assert_eq!(msg.chaddr().len(), 16);
        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_json() -> Result<()> {
        let msg = Message::decode(&mut Decoder::new(&offer()))?;
        let s = serde_json::to_string_pretty(&msg)?;
        println!("{s}");
        let other = serde_json::from_str(&s)?;
        assert_eq!(msg, other);
        Ok(())
    }

    /// Build a raw DHCPv4 message with the given option-52 overload value and the
    /// given raw contents placed in the `sname`/`file` fields and the main
    /// options area. The overload option and an `End` are appended to `main_opts`.
    fn overload_msg(
        overload: u8,
        main_opts: &[u8],
        sname_opts: &[u8],
        file_opts: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[1, 1, 6, 0]); // op, htype, hlen, hops
        v.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // xid
        v.extend_from_slice(&[0, 0]); // secs
        v.extend_from_slice(&[0, 0]); // flags
        v.extend_from_slice(&[0; 16]); // ciaddr, yiaddr, siaddr, giaddr
        v.extend_from_slice(&[0; 16]); // chaddr
        let mut sname = [0u8; 64];
        sname[..sname_opts.len()].copy_from_slice(sname_opts);
        v.extend_from_slice(&sname);
        let mut file = [0u8; 128];
        file[..file_opts.len()].copy_from_slice(file_opts);
        v.extend_from_slice(&file);
        v.extend_from_slice(&MAGIC);
        v.extend_from_slice(main_opts);
        v.extend_from_slice(&[52, 1, overload]); // option overload
        v.push(255); // end
        v
    }

    #[test]
    fn decode_option_overload_both() -> Result<()> {
        // sname holds Hostname("host"), file holds DomainName("example")
        let sname_opts = [12u8, 4, b'h', b'o', b's', b't', 255];
        let file_opts = [15u8, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 255];
        let bytes = overload_msg(3, &[53, 1, 1], &sname_opts, &file_opts);
        let msg = Message::decode(&mut Decoder::new(&bytes))?;

        assert_eq!(msg.opts().msg_type(), Some(MessageType::Discover));
        assert_eq!(
            msg.opts().get(OptionCode::Hostname),
            Some(&DhcpOption::Hostname(b"host".to_vec()))
        );
        assert_eq!(
            msg.opts().get(OptionCode::DomainName),
            Some(&DhcpOption::DomainName(b"example".to_vec()))
        );
        // marker stripped; fields consumed as options
        assert!(!msg.opts().contains(OptionCode::OptionOverload));
        assert!(msg.sname().is_none());
        assert!(msg.fname().is_none());
        Ok(())
    }

    #[test]
    fn decode_option_overload_file_only() -> Result<()> {
        let file_opts = [15u8, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 255];
        // value 1 overloads only `file`; sname stays a plain (nul-terminated) name
        let bytes = overload_msg(1, &[53, 1, 1], b"myhost", &file_opts);
        let msg = Message::decode(&mut Decoder::new(&bytes))?;

        assert_eq!(
            msg.opts().get(OptionCode::DomainName),
            Some(&DhcpOption::DomainName(b"example".to_vec()))
        );
        // sname preserved (matches read_nul_bytes: includes the terminating NUL)
        assert_eq!(msg.sname(), Some(&b"myhost\0"[..]));
        // sname was NOT parsed as options
        assert!(!msg.opts().contains(OptionCode::Hostname));
        Ok(())
    }

    #[test]
    fn decode_option_overload_sname_only() -> Result<()> {
        let sname_opts = [12u8, 4, b'h', b'o', b's', b't', 255];
        // value 2 overloads only `sname`; file stays a plain (nul-terminated) name
        let bytes = overload_msg(2, &[53, 1, 1], &sname_opts, b"boot.img");
        let msg = Message::decode(&mut Decoder::new(&bytes))?;

        assert_eq!(
            msg.opts().get(OptionCode::Hostname),
            Some(&DhcpOption::Hostname(b"host".to_vec()))
        );
        assert_eq!(msg.fname(), Some(&b"boot.img\0"[..]));
        assert!(!msg.opts().contains(OptionCode::DomainName));
        Ok(())
    }

    #[test]
    fn decode_option_overload_rfc3396_split() -> Result<()> {
        // A DomainName whose value is split across the `file` (part 1) and
        // `sname` (part 2) regions must be reassembled per RFC 3396. Each region
        // holds one same-code fragment; after concatenation the value is "abcdef".
        let file_opts = [15u8, 3, b'a', b'b', b'c', 255];
        let sname_opts = [15u8, 3, b'd', b'e', b'f', 255];
        let bytes = overload_msg(3, &[53, 1, 1], &sname_opts, &file_opts);
        let msg = Message::decode(&mut Decoder::new(&bytes))?;

        assert_eq!(
            msg.opts().get(OptionCode::DomainName),
            Some(&DhcpOption::DomainName(b"abcdef".to_vec()))
        );
        Ok(())
    }

    #[test]
    fn decode_option_overload_rfc3396_split_main_to_file() -> Result<()> {
        // Part 1 is the last real option in the MAIN field; the option-52 marker
        // (appended after it by overload_msg) sits between the fragments on the
        // wire. Reassembly must still span main -> file across that marker.
        let main = [53u8, 1, 1, 15, 3, b'a', b'b', b'c'];
        let file_opts = [15u8, 3, b'd', b'e', b'f', 255];
        let bytes = overload_msg(1, &main, &[], &file_opts);
        let msg = Message::decode(&mut Decoder::new(&bytes))?;

        assert_eq!(
            msg.opts().get(OptionCode::DomainName),
            Some(&DhcpOption::DomainName(b"abcdef".to_vec()))
        );
        Ok(())
    }

    #[test]
    fn decode_option_overload_split_across_padded_region() -> Result<()> {
        // The file field holds part 1 but is not End-terminated, so overload_msg
        // zero-pads it. Those Pad bytes must not break reassembly with part 2 in
        // the sname field.
        let file_opts = [15u8, 3, b'a', b'b', b'c']; // no End -> Pad-filled
        let sname_opts = [15u8, 3, b'd', b'e', b'f', 255];
        let bytes = overload_msg(3, &[53, 1, 1], &sname_opts, &file_opts);
        let msg = Message::decode(&mut Decoder::new(&bytes))?;

        assert_eq!(
            msg.opts().get(OptionCode::DomainName),
            Some(&DhcpOption::DomainName(b"abcdef".to_vec()))
        );
        Ok(())
    }

    #[test]
    fn decode_option_overload_empty_fields() -> Result<()> {
        // overload says "both", but the fields are all zero (Pad) - a no-op
        let bytes = overload_msg(3, &[53, 1, 1], &[], &[]);
        let msg = Message::decode(&mut Decoder::new(&bytes))?;

        assert_eq!(msg.opts().msg_type(), Some(MessageType::Discover));
        assert!(!msg.opts().contains(OptionCode::OptionOverload));
        assert!(msg.sname().is_none());
        assert!(msg.fname().is_none());
        Ok(())
    }

    #[test]
    fn decode_option_overload_absent() -> Result<()> {
        // No option 52: sname/file are ordinary name fields and are NOT parsed
        // as options even if they happen to look like one.
        let bytes = overload_msg(0, &[53, 1, 1], b"srv", b"boot.img");
        // overload_msg still appends `52,1,0`; a zero value means "not overloaded"
        let msg = Message::decode(&mut Decoder::new(&bytes))?;

        assert_eq!(msg.sname(), Some(&b"srv\0"[..]));
        assert_eq!(msg.fname(), Some(&b"boot.img\0"[..]));
        // a zero-valued overload option is left as-is in the map
        assert!(msg.opts().contains(OptionCode::OptionOverload));
        Ok(())
    }

    fn offer() -> Vec<u8> {
        vec![
            0x02, 0x01, 0x06, 0x00, 0x00, 0x00, 0x15, 0x5c, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xc0, 0xa8, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xcc, 0x00, 0x0a, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
            0x53, 0x63, 0x35, 0x01, 0x02, 0x36, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0x33, 0x04, 0x00,
            0x00, 0x00, 0x3c, 0x3a, 0x04, 0x00, 0x00, 0x00, 0x1e, 0x3b, 0x04, 0x00, 0x00, 0x00,
            0x34, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0x06,
            0x08, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x01, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }
    fn bootreq() -> Vec<u8> {
        vec![
            1u8, // op
            2,   // htype
            3,   // hlen
            4,   // ops
            5, 6, 7, 8, // xid
            9, 10, // secs
            11, 12, // flags
            13, 14, 15, 16, // ciaddr
            17, 18, 19, 20, // yiaddr
            21, 22, 23, 24, // siaddr
            25, 26, 27, 28, // giaddr
            29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, // chaddr
            45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,
            67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
            89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
            0, // sname: "-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk",
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
            109, 0, 0, 0, 0, 0, 0, 0,
            0, // file: "mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}mnopqrstuvwxyz{|}m",
            99, 130, 83, 99, // magic cookie
        ]
    }
    fn discover() -> Vec<u8> {
        vec![
            0x01, 0x01, 0x06, 0x00, 0xa6, 0x80, 0x56, 0x74, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xde, 0xad, 0xc0, 0xde, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
            0x53, 0x63, 0x35, 0x01, 0x01, 0x37, 0x40, 0xfc, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
            0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
            0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x43,
            0x42, 0x33, 0x04, 0x00, 0x00, 0x00, 0x01, 0xff,
        ]
    }
    fn other_offer() -> Vec<u8> {
        vec![
            0x02, 0x01, 0x06, 0x00, 0xa6, 0x80, 0x56, 0x74, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xc0, 0xa8, 0x00, 0x95, 0xc0, 0xa8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0xde, 0xad, 0xc0, 0xde, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82,
            0x53, 0x63, 0x35, 0x01, 0x02, 0x36, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0x33, 0x04, 0x00,
            0x00, 0x00, 0x78, 0x3a, 0x04, 0x00, 0x00, 0x00, 0x3c, 0x3b, 0x04, 0x00, 0x00, 0x00,
            0x69, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x1c, 0x04, 0xc0, 0xa8, 0x00, 0xff, 0x06,
            0x04, 0xc0, 0xa8, 0x00, 0x01, 0x03, 0x04, 0xc0, 0xa8, 0x00, 0x01, 0xff, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }
}
