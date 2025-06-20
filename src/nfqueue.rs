/*
 * nfqueue.rs - Netfilter Queue (NFQUEUE) interface for nf_wgobfs
 *
 * Copyright (c) 2025 sh0rch <sh0rch@iwl.dev>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//! Netfilter Queue (NFQUEUE) interface for Rust
//!
//! This module provides low-level bindings and helpers for interacting with the Linux Netfilter
//! NFQUEUE subsystem via netlink sockets. It allows spawning queue handlers, receiving packets,
//! and sending verdicts (accept/drop/modify) back to the kernel.
//!
//! # Safety
//!
//! Many functions in this module are unsafe and require careful use, as they interact directly
//! with kernel memory and system calls.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::{mem, ptr, slice};
use libc::{
    __errno_location, _exit, bind, c_int, c_void, close, fork, getpid, iovec, msghdr, nlattr,
    nlmsghdr, pause, recv, sendmsg, sendto, setsockopt, socket, AF_NETLINK, AF_UNSPEC,
    NETLINK_NETFILTER, NETLINK_NO_ENOBUFS, NFNETLINK_V0, NFNL_SUBSYS_QUEUE, NFQA_CFG_CMD,
    NFQA_CFG_FLAGS, NFQA_CFG_F_CONNTRACK, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_GSO, NFQA_CFG_F_SECCTX,
    NFQA_CFG_F_UID_GID, NFQA_CFG_MASK, NFQA_CFG_PARAMS, NFQA_CFG_QUEUE_MAXLEN, NFQA_PACKET_HDR,
    NFQA_PAYLOAD, NFQA_VERDICT_HDR, NFQNL_CFG_CMD_BIND, NFQNL_CFG_CMD_UNBIND, NFQNL_MSG_CONFIG,
    NFQNL_MSG_PACKET, NFQNL_MSG_VERDICT, NF_ACCEPT, NF_DROP, NLM_F_ACK, NLM_F_REQUEST, SOCK_RAW,
    SOL_NETLINK,
};

/// Default mask for queue configuration (big-endian)
const DEFAULT_MASK_BE: u32 = ((NFQA_CFG_F_FAIL_OPEN
    | NFQA_CFG_F_GSO
    | NFQA_CFG_F_SECCTX
    | NFQA_CFG_F_UID_GID
    | NFQA_CFG_F_CONNTRACK) as u32)
    .to_be();

/// Default copy range for queue configuration (big-endian)
const DEFAULT_COPY_RANGE_BE: u32 = (0xFFFFu32).to_be();

/// MSG_NOSIGNAL flag for sendmsg
const MSG_NOSIGNAL: i32 = 0x4000;

/// Kernel netlink address (pid=0)
static KERNEL: sockaddr_nl =
    sockaddr_nl { nl_family: AF_NETLINK as u16, nl_pad: 0, nl_pid: 0, nl_groups: 0 };

/// Aligns a value to the next multiple of 4
#[inline(always)]
const fn a4(n: usize) -> usize {
    (n + 3) & !3
}

/// Returns the current value of errno
#[inline]
fn errno() -> c_int {
    unsafe { *__errno_location() }
}

/// Constructs a netlink message type from subsystem and command
#[inline]
const fn nlmsg_type(sub: u16, cmd: u8) -> u16 {
    (sub << 8) | cmd as u16
}

/// Converts a reference to a type into a byte slice
#[inline(always)]
unsafe fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    core::slice::from_raw_parts(v as *const _ as *const u8, core::mem::size_of::<T>())
}

/// sockaddr_nl structure for netlink sockets
#[repr(C)]
pub struct sockaddr_nl {
    pub nl_family: u16,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

/// Template for a verdict message (header + payload attribute)
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct VerdictTpl {
    hdr: HeaderTpl,
    pay_hdr: nlattr,
}
impl VerdictTpl {
    /// Creates a new verdict template for the given queue
    const fn new(queue: u16) -> Self {
        Self {
            hdr: HeaderTpl::new(queue),
            pay_hdr: nlattr { nla_len: 0, nla_type: NFQA_PAYLOAD as u16 },
        }
    }
}

/// Template for a netlink message header for verdicts
#[repr(C)]
#[derive(Copy, Clone)]
struct HeaderTpl {
    nlh: nlmsghdr,
    gen: NfGenMsg,
    a_v: nlattr,
    vhdr: NfqVerdictHdr,
}
impl HeaderTpl {
    /// Creates a new header template for the given queue
    const fn new(queue: u16) -> Self {
        HeaderTpl {
            nlh: nlmsghdr {
                nlmsg_len: 0,
                nlmsg_type: nlmsg_type(NFNL_SUBSYS_QUEUE as u16, NFQNL_MSG_VERDICT as u8),
                nlmsg_flags: NLM_F_REQUEST as u16,
                nlmsg_seq: 0,
                nlmsg_pid: 0,
            },
            gen: NfGenMsg {
                family: AF_UNSPEC as u8,
                ver: NFNETLINK_V0 as u8,
                res_id: queue.to_be(),
            },
            a_v: nlattr {
                nla_len: (core::mem::size_of::<nlattr>() + core::mem::size_of::<NfqVerdictHdr>())
                    as u16,
                nla_type: NFQA_VERDICT_HDR as u16,
            },
            vhdr: NfqVerdictHdr { verdict: 0, id: 0 },
        }
    }
}

/// Netfilter generic message header
#[repr(C)]
#[derive(Copy, Clone)]
struct NfGenMsg {
    family: u8,
    ver: u8,
    res_id: u16,
}

/// Netfilter queue configuration command
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NfqCfgCmd {
    pub command: u8,
    pub _pad: u8,
    pub pf: u16,
}

impl NfqCfgCmd {
    /// Returns a bind command
    pub const fn bind() -> Self {
        Self { command: NFQNL_CFG_CMD_BIND as u8, _pad: 0, pf: AF_UNSPEC as u16 }
    }
    /// Returns an unbind command
    pub const fn unbind() -> Self {
        Self { command: NFQNL_CFG_CMD_UNBIND as u8, _pad: 0, pf: AF_UNSPEC as u16 }
    }
}

/// Netfilter queue configuration parameters
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NfqCfgParams {
    copy_range: u32,
    copy_mode: u8,
    _pad: u8,
}

impl Default for NfqCfgParams {
    #[inline]
    fn default() -> Self {
        Self { copy_range: DEFAULT_COPY_RANGE_BE, copy_mode: 2, _pad: 0 }
    }
}

/// Netfilter queue verdict header
#[repr(C)]
#[derive(Copy, Clone)]
struct NfqVerdictHdr {
    verdict: u32,
    id: u32,
}

/// Netfilter hook points
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
#[repr(u8)]
pub enum Hook {
    PreRouting = 0,
    LocalIn = 1,
    Forward = 2,
    LocalOut = 3,
    PostRouting = 4,
    Ingress = 5,
    Unknown = 0xFF,
}

impl From<u8> for Hook {
    #[inline]
    fn from(h: u8) -> Self {
        match h {
            0 => Hook::PreRouting,
            1 => Hook::LocalIn,
            2 => Hook::Forward,
            3 => Hook::LocalOut,
            4 => Hook::PostRouting,
            5 => Hook::Ingress,
            _ => Hook::Unknown,
        }
    }
}

/// Buffer for queue messages and packet data
pub struct QueueBuf {
    data: Vec<u8>,
    cur: usize,
    seq: u32,
}
impl QueueBuf {
    /// Creates a new buffer with the given MTU
    pub fn new(mtu: usize) -> Self {
        let cap = mtu.checked_mul(2).unwrap_or(mtu);
        let data = vec![0u8; cap];

        Self { data, cur: 0, seq: 1 }
    }

    /// Returns a mutable pointer to the buffer base
    #[inline]
    fn base(&self) -> *mut u8 {
        self.data.as_ptr() as *mut u8
    }

    /// Appends a payload to the buffer (unsafe, no bounds check)
    #[inline]
    pub unsafe fn put(&mut self, payload: &[u8]) {
        debug_assert!(self.cur + payload.len() <= self.data.len());
        ptr::copy_nonoverlapping(payload.as_ptr(), self.base().add(self.cur), payload.len());
        self.cur += payload.len();
    }

    /// Appends a netlink attribute with the given type and payload
    #[inline]
    pub unsafe fn put_attr(&mut self, nla_type: u16, payload: &[u8]) {
        let hdr = nlattr { nla_len: (mem::size_of::<nlattr>() + payload.len()) as u16, nla_type };
        self.put(slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<nlattr>()));
        self.put(payload);
        self.cur = (self.cur + 3) & !3;
    }

    /// Clears the buffer
    #[inline]
    pub fn clear(&mut self) {
        self.cur = 0;
    }
    /// Returns and increments the sequence number
    #[inline]
    pub fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1;
        }
        s
    }
}

/// Information about a received packet
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PacketInfo {
    pub id: u32,
    pub family: u8,
    pub hook: Hook,
    pub payload_off: usize,
    pub payload_len: usize,
}

/// Represents a single NFQUEUE instance
pub struct NfqQueue {
    fd: i32,
    num: u16,
    buf: QueueBuf,
    pkt: Option<PacketInfo>,
}

impl NfqQueue {
    /// Spawns a new process and initializes an NFQUEUE handler in the child.
    /// The child_fn is called with a mutable reference to the queue.
    pub fn spawn<F>(num: u16, qlen: u32, mtu: usize, child_fn: F) -> Result<i32, i32>
    where
        F: FnOnce(&mut NfqQueue) + 'static,
    {
        let pid = unsafe { fork() };
        if pid < 0 {
            return Err(errno());
        }
        if pid == 0 {
            unsafe {
                match Self::init(num, qlen, mtu) {
                    Ok(mut q) => {
                        child_fn(&mut q);
                        _exit(0);
                    }
                    Err(code) => {
                        _exit(code);
                    }
                }
            }
        }
        Ok(pid)
    }

    /// Initializes a new NFQUEUE instance with the given parameters.
    /// Returns a queue object on success.
    pub unsafe fn init(num: u16, queue_maxlen: u32, mtu: usize) -> Result<Self, i32> {
        let fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
        if fd < 0 {
            eprintln!("NFQUEUE socket error, errno {}", errno());
            return Err(errno());
        }
        let mut addr: sockaddr_nl = unsafe { core::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = getpid() as u32;
        if bind(fd, &addr as *const _ as *const _, core::mem::size_of::<sockaddr_nl>() as u32) < 0 {
            let e = errno();
            let _ = close(fd);
            eprintln!("NFQUEUE bind error, errno {e}");
            return Err(e);
        }
        let opt: u32 = 1;
        if setsockopt(
            fd,
            SOL_NETLINK,
            NETLINK_NO_ENOBUFS,
            &opt as *const _ as *const c_void,
            core::mem::size_of::<u32>() as u32,
        ) < 0
        {
            let e = errno();
            let _ = close(fd);
            return Err(e);
        }
        let mut q = NfqQueue { fd, num, buf: QueueBuf::new(mtu), pkt: None };
        {
            q.buf.clear();
            write_cfg_cmd(&mut q.buf, num, NfqCfgCmd::bind());
            let ptr = q.buf.base();
            if q.send_simple(ptr, q.buf.cur) < 0 {
                return Err(errno());
            }
        }
        {
            q.buf.clear();
            write_cfg_defaults(&mut q.buf, num, AF_UNSPEC as u16, queue_maxlen);
            let ptr = q.buf.base();
            if q.send_simple(ptr, q.buf.cur) < 0 {
                return Err(errno());
            }
        }
        Ok(q)
    }

    /// Sends a simple netlink message to the kernel
    unsafe fn send_simple(&self, buf: *const u8, len: usize) -> isize {
        let mut addr: sockaddr_nl = unsafe { core::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0;
        sendto(
            self.fd,
            buf as *const _,
            len,
            0,
            &addr as *const _ as *const _,
            core::mem::size_of::<sockaddr_nl>() as u32,
        )
    }

    /// Receives a packet from the queue and parses its info
    pub fn recv(&mut self) -> Result<PacketInfo, i32> {
        unsafe {
            let cap = self.buf.data.len();
            let n = recv(self.fd, self.buf.base() as *mut c_void, cap, 0);
            if n < 0 {
                return Err(errno());
            }
            self.buf.cur = n as usize;
            match parse_packet(&mut self.buf) {
                Ok(pkt) => {
                    self.pkt = Some(pkt);
                    Ok(pkt)
                }
                Err(e) => {
                    self.pkt = None;
                    Err(e)
                }
            }
        }
    }

    /// Sends a verdict for the current packet, optionally with a payload
    pub unsafe fn send_verdict(
        &mut self,
        verdict: u32,
        payload_len: Option<usize>,
    ) -> Result<(), i32> {
        let mut tpl = VerdictTpl::new(self.num);
        tpl.hdr.vhdr.verdict = verdict.to_be();
        tpl.hdr.vhdr.id = self.pkt.as_ref().ok_or(-1)?.id.to_be();

        let pad = payload_len.map(|l| a4(l) - l).unwrap_or(0);
        let data_len = payload_len.unwrap_or(0) + pad;

        tpl.pay_hdr.nla_len = (core::mem::size_of::<nlattr>() + data_len) as u16;
        tpl.hdr.nlh.nlmsg_len = (core::mem::size_of::<VerdictTpl>() + data_len) as u32;
        tpl.hdr.nlh.nlmsg_seq = self.buf.next_seq();

        let iov = [
            iovec {
                iov_base: &tpl as *const _ as *mut _,
                iov_len: core::mem::size_of::<VerdictTpl>(),
            },
            iovec { iov_base: self.payload_ptr() as *mut c_void, iov_len: data_len },
        ];
        let iovcnt = if data_len == 0 { 1 } else { 2 };
        let msg = make_msghdr(iov.as_ptr() as *mut iovec, iovcnt);
        if sendmsg(self.fd, &msg, MSG_NOSIGNAL) < 0 {
            Err(errno())
        } else {
            Ok(())
        }
    }

    /// Accepts the current packet, optionally modifying its length
    pub fn accept_pkt(&mut self, new_len: usize) -> Result<(), i32> {
        unsafe { self.send_verdict(NF_ACCEPT as u32, Some(new_len)) }
    }

    /// Drops the current packet
    pub fn drop_pkt(&mut self) -> Result<(), i32> {
        unsafe { self.send_verdict(NF_DROP as u32, None) }
    }

    /// Returns a mutable slice to the packet payload
    #[inline(always)]
    pub unsafe fn payload_mut(&mut self) -> &mut [u8] {
        let cap = self.buf.data.len();
        let pkt = match self.pkt {
            Some(pkt) => pkt,
            None => panic!("No packet info available"),
        };
        core::slice::from_raw_parts_mut(self.buf.base().add(pkt.payload_off), cap)
    }

    /// Returns a pointer to the packet payload
    #[inline(always)]
    unsafe fn payload_ptr(&self) -> *mut u8 {
        let pkt = self.pkt.as_ref().unwrap();
        self.buf.base().add(pkt.payload_off)
    }
}

impl Drop for NfqQueue {
    /// Cleans up the queue, unbinds and closes the socket
    fn drop(&mut self) {
        self.buf.clear();
        unsafe {
            write_cfg_cmd(&mut self.buf, self.num, NfqCfgCmd::unbind());
            let base = self.buf.base();
            let _ = self.send_simple(base, self.buf.cur);
            let _ = close(self.fd);
            _exit(0);
        }
    }
}

/// Writes a configuration command message to the buffer
pub fn write_cfg_cmd(buf: &mut QueueBuf, queue: u16, cmd: NfqCfgCmd) {
    let hdr_ofs = buf.cur;
    buf.cur += mem::size_of::<nlmsghdr>();
    let gen = NfGenMsg { family: cmd.pf as u8, ver: 0, res_id: queue };
    unsafe {
        buf.put(slice::from_raw_parts(&gen as *const _ as *const u8, mem::size_of::<NfGenMsg>()))
    };
    unsafe {
        buf.put_attr(
            NFQA_CFG_CMD as u16,
            slice::from_raw_parts(&cmd as *const _ as *const u8, mem::size_of::<NfqCfgCmd>()),
        )
    };
    finish_hdr(buf, hdr_ofs);
}

/// Writes default configuration parameters to the buffer
pub fn write_cfg_defaults(buf: &mut QueueBuf, queue: u16, family: u16, qlen: u32) {
    let hdr_ofs = buf.cur;
    buf.cur += core::mem::size_of::<nlmsghdr>();

    let gen = NfGenMsg { family: family as u8, ver: 0, res_id: queue.to_be() };
    unsafe {
        buf.put(as_bytes(&gen));
    }

    let params = NfqCfgParams::default();
    unsafe {
        buf.put_attr(NFQA_CFG_PARAMS as u16, as_bytes(&params));
    }

    let mask = DEFAULT_MASK_BE;
    unsafe {
        buf.put_attr(NFQA_CFG_MASK as u16, as_bytes(&mask));
    }

    let flags = 0u32;
    unsafe {
        buf.put_attr(NFQA_CFG_FLAGS as u16, as_bytes(&flags));
    }

    unsafe {
        buf.put_attr(NFQA_CFG_QUEUE_MAXLEN as u16, &qlen.to_be_bytes());
    }

    finish_hdr(buf, hdr_ofs);
}

/// Finalizes the netlink message header in the buffer
#[inline]
fn finish_hdr(buf: &mut QueueBuf, hdr_ofs: usize) {
    let len = (buf.cur - hdr_ofs) as u32;
    unsafe {
        write_nlmsghdr(
            buf.base().add(hdr_ofs),
            nlmsg_type(NFNL_SUBSYS_QUEUE as u16, NFQNL_MSG_CONFIG as u8),
            len,
            buf.next_seq(),
            (NLM_F_REQUEST | NLM_F_ACK) as u16,
        );
    }
    buf.cur = (buf.cur + 3) & !3;
}

/// Writes a netlink message header at the given destination
#[inline(always)]
pub unsafe fn write_nlmsghdr(dst: *mut u8, nlmsg_type: u16, nlmsg_len: u32, seq: u32, flags: u16) {
    debug_assert!(nlmsg_len >= size_of::<nlmsghdr>() as u32);
    let hdr = &mut *(dst as *mut nlmsghdr);
    hdr.nlmsg_len = nlmsg_len;
    hdr.nlmsg_type = nlmsg_type;
    hdr.nlmsg_flags = flags;
    hdr.nlmsg_seq = seq;
    hdr.nlmsg_pid = 0;
}

/// Parses a received netlink packet and extracts packet info
#[inline(always)]
unsafe fn parse_packet(buf: &mut QueueBuf) -> Result<PacketInfo, i32> {
    let nl = &*(buf.base() as *const nlmsghdr);
    if nl.nlmsg_type != nlmsg_type(NFNL_SUBSYS_QUEUE as u16, NFQNL_MSG_PACKET as u8) {
        return Err(-2);
    }

    let gen = &*(buf.base().add(core::mem::size_of::<nlmsghdr>()) as *const NfGenMsg);
    let family = gen.family;

    let mut p = buf.base().add(core::mem::size_of::<nlmsghdr>() + core::mem::size_of::<NfGenMsg>())
        as *const nlattr;
    let end = buf.base().add(buf.cur);

    let mut id = 0u32;
    let mut hook_byte = 0u8;
    let mut pay_off = 0usize;
    let mut pay_len = 0usize;

    while (p as *const u8) < end {
        let alen = (*p).nla_len as usize;
        let atype = (*p).nla_type;
        let data = (p as *const u8).add(core::mem::size_of::<nlattr>());

        match atype {
            x if x == NFQA_PACKET_HDR as u16 => {
                id = u32::from_be(ptr::read_unaligned(data as *const u32));
                hook_byte = *data.add(6);
            }
            x if x == NFQA_PAYLOAD as u16 => {
                pay_off = data as usize - buf.base() as usize;
                pay_len = alen - core::mem::size_of::<nlattr>();
                break;
            }
            _ => {}
        }
        p = (p as *const u8).add(a4(alen)) as *const nlattr;
    }

    if pay_len == 0 {
        Err(-1)
    } else {
        Ok(PacketInfo {
            id,
            family,
            hook: Hook::from(hook_byte),
            payload_off: pay_off,
            payload_len: pay_len,
        })
    }
}

/// Constructs a msghdr for sendmsg
#[inline]
fn make_msghdr(iov: *mut iovec, iovcnt: usize) -> msghdr {
    let mut msg: msghdr = unsafe { mem::zeroed() };

    msg.msg_name = &KERNEL as *const _ as *mut _;
    msg.msg_namelen = mem::size_of::<sockaddr_nl>() as _;
    msg.msg_iov = iov;
    msg.msg_iovlen = iovcnt as _;
    msg.msg_control = ptr::null_mut();
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    msg
}

/// Waits forever until a signal is received (used in child processes)
pub fn wait_forever_until_signal() {
    loop {
        let rc = unsafe { pause() };
        if rc == -1 {
            break;
        }
    }
}

#[cfg(not(test))]
#[cfg(not(feature = "std"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
