use std::{
    error::Error,
    ffi::CString,
    net::IpAddr,
    os::raw::c_void,
};

use log::info;
use nftnl::ProtoFamily;

/// Wrapper around nftables for managing IP ban sets with timeouts.
/// Uses raw nftnl-sys FFI for low-level netlink communication.
/// Each add operation immediately sends to nftables (no batching).
pub struct NftSession {
    table: String,
    set: String,
    family: ProtoFamily,
}

impl NftSession {
    /// Create a new nftables session for a specific set.
    ///
    /// # Arguments
    /// * `table` - The nftables table name (e.g., "leroy")
    /// * `set` - The set name within the table (e.g., "leroy4" or "leroy6")
    /// * `family` - The IP family (ProtoFamily::Ipv4 or ProtoFamily::Ipv6)
    pub fn new(table: String, set: String, family: ProtoFamily) -> Self {
        NftSession {
            table,
            set,
            family,
        }
    }

    /// Add an IP address to the set with a specific timeout.
    /// Immediately sends to nftables via netlink (no batching).
    ///
    /// # Arguments
    /// * `ip` - The IP address to ban
    /// * `timeout_secs` - The timeout in seconds
    ///
    /// # Returns
    /// * `Ok(true)` - Element was added successfully
    /// * `Err(_)` - Failed to add element
    pub fn add(&mut self, ip: IpAddr, timeout_secs: u32) -> Result<bool, Box<dyn Error>> {
        info!(
            target: "leroyjenkins",
            "Adding {} to set {} with timeout {}s",
            ip, self.set, timeout_secs
        );

        unsafe {
            self.add_element_with_timeout_raw(ip, timeout_secs)?;
        }

        Ok(true)
    }

    /// Add an element with timeout using raw nftnl-sys FFI and manual netlink message construction.
    /// This is necessary because nftnl's safe API doesn't expose element timeout functionality.
    unsafe fn add_element_with_timeout_raw(
        &self,
        ip: IpAddr,
        timeout_secs: u32,
    ) -> Result<(), Box<dyn Error>> {
        let set_name = CString::new(self.set.as_str())?;
        let table_name = CString::new(self.table.as_str())?;

        // Create nftnl_set for holding elements
        let set_ptr = nftnl_sys::nftnl_set_alloc();
        if set_ptr.is_null() {
            return Err("Failed to allocate nftnl_set".into());
        }

        // Set required set attributes
        nftnl_sys::nftnl_set_set_str(
            set_ptr,
            nftnl_sys::NFTNL_SET_NAME as u16,
            set_name.as_ptr(),
        );
        nftnl_sys::nftnl_set_set_str(
            set_ptr,
            nftnl_sys::NFTNL_SET_TABLE as u16,
            table_name.as_ptr(),
        );
        nftnl_sys::nftnl_set_set_u32(
            set_ptr,
            nftnl_sys::NFTNL_SET_FAMILY as u16,
            self.family as u32,
        );

        // Create set element
        let elem_ptr = nftnl_sys::nftnl_set_elem_alloc();
        if elem_ptr.is_null() {
            nftnl_sys::nftnl_set_free(set_ptr);
            return Err("Failed to allocate nftnl_set_elem".into());
        }

        // Set the IP address key
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                nftnl_sys::nftnl_set_elem_set(
                    elem_ptr,
                    nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                    octets.as_ptr() as *const c_void,
                    octets.len() as u32,
                );
            }
            IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                nftnl_sys::nftnl_set_elem_set(
                    elem_ptr,
                    nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                    octets.as_ptr() as *const c_void,
                    octets.len() as u32,
                );
            }
        }

        // Set timeout in milliseconds (nftables kernel uses ms)
        let timeout_ms = (timeout_secs as u64).saturating_mul(1000);
        nftnl_sys::nftnl_set_elem_set_u64(
            elem_ptr,
            nftnl_sys::NFTNL_SET_ELEM_TIMEOUT as u16,
            timeout_ms,
        );

        // Add element to set
        nftnl_sys::nftnl_set_elem_add(set_ptr, elem_ptr);

        // Build and send netlink message
        let result = self.send_set_elem_message(set_ptr);

        // Clean up (elem_ptr is owned by set_ptr, so only free set)
        nftnl_sys::nftnl_set_free(set_ptr);

        result
    }

    /// Build netlink message for set elements and send via mnl socket.
    unsafe fn send_set_elem_message(&self, set_ptr: *mut nftnl_sys::nftnl_set) -> Result<(), Box<dyn Error>> {
        use mnl::mnl_sys;

        // Netlink message flags (from linux/netlink.h)
        const NLM_F_REQUEST: u16 = 1;
        const NLM_F_ACK: u16 = 4;
        const NLM_F_CREATE: u16 = 0x400;

        // Nftables message types (from linux/netfilter/nfnetlink.h)
        const NFNL_SUBSYS_NFTABLES: u16 = 10;
        const NFT_MSG_NEWSETELEM: u16 = 13;

        // Allocate netlink message buffer (using typical MTU size)
        const MNL_SOCKET_BUFFER_SIZE: usize = 8192;
        let mut buf = vec![0u8; MNL_SOCKET_BUFFER_SIZE];

        // Build netlink message header using mnl_sys
        #[repr(C)]
        struct nlmsghdr {
            nlmsg_len: u32,
            nlmsg_type: u16,
            nlmsg_flags: u16,
            nlmsg_seq: u32,
            nlmsg_pid: u32,
        }

        let nlh = mnl_sys::mnl_nlmsg_put_header(buf.as_mut_ptr() as *mut c_void) as *mut nlmsghdr;

        // Set message type: NFT_MSG_NEWSETELEM with NFNL_SUBSYS_NFTABLES subsystem
        (*nlh).nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;
        (*nlh).nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
        (*nlh).nlmsg_seq = 1;

        // Build message payload with set elements
        nftnl_sys::nftnl_set_elems_nlmsg_build_payload(nlh as *mut _, set_ptr);

        // Open netlink socket
        let socket = mnl::Socket::new(mnl::Bus::Netfilter)
            .map_err(|e| format!("Failed to open netlink socket: {}", e))?;

        // Send message
        let msg_len = (*nlh).nlmsg_len as usize;
        let msg_slice = &buf[..msg_len];
        socket.send_all(vec![msg_slice])
            .map_err(|e| format!("Failed to send netlink message: {}", e))?;

        // Receive and check acknowledgment
        let mut recv_buf = vec![0u8; MNL_SOCKET_BUFFER_SIZE];
        let bytes_received = socket.recv(&mut recv_buf)
            .map_err(|e| format!("Failed to receive netlink response: {}", e))?;

        // Parse response to check for errors
        // For now, we just check if we got a response
        if bytes_received == 0 {
            return Err("Received empty netlink response".into());
        }

        Ok(())
    }
}
