use std::{
    error::Error,
    ffi::CString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use log::info;
use nftnl::{Batch, MsgType, ProtoFamily, Table, set::Set};

/// Wrapper around nftables for managing IP ban sets with timeouts.
/// Uses safe nftnl API with netlink batching.
pub struct NftSession {
    table_name: CString,
    set_name: CString,
    family: ProtoFamily,
    socket: mnl::Socket,
}

impl NftSession {
    /// Create a new nftables session for a specific set.
    ///
    /// # Arguments
    /// * `table` - The nftables table name (e.g., "leroy")
    /// * `set` - The set name within the table (e.g., "leroy4" or "leroy6")
    /// * `family` - The IP family (ProtoFamily::Ipv4 or ProtoFamily::Ipv6)
    pub fn new(table: String, set: String, family: ProtoFamily) -> Result<Self, Box<dyn Error>> {
        let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
        Ok(NftSession {
            table_name: CString::new(table)?,
            set_name: CString::new(set)?,
            family,
            socket,
        })
    }

    /// Add an IP address to the set with a specific timeout.
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
            ip, self.set_name.to_string_lossy(), timeout_secs
        );

        // Convert timeout to milliseconds
        let timeout_ms = (timeout_secs as u64).saturating_mul(1000);

        // Create table reference
        let table = Table::new(&self.table_name, self.family);

        // Create batch for atomic operation
        let mut batch = Batch::new();

        // Add element based on IP version
        // Note: Using Set::new() with dummy id 0. The ANONYMOUS/CONSTANT flags don't
        // matter since we only send elements (NFT_MSG_NEWSETELEM), not set definition.
        match ip {
            IpAddr::V4(ipv4) => {
                let mut set = Set::<Ipv4Addr>::new(
                    &self.set_name,
                    0,
                    &table,
                    self.family,
                );
                set.add_with_timeout(&ipv4, Some(timeout_ms));

                // Add set elements to batch
                for msg in set.elems_iter() {
                    batch.add(&msg, MsgType::Add);
                }
            }
            IpAddr::V6(ipv6) => {
                let mut set = Set::<Ipv6Addr>::new(
                    &self.set_name,
                    0,
                    &table,
                    self.family,
                );
                set.add_with_timeout(&ipv6, Some(timeout_ms));

                // Add set elements to batch
                for msg in set.elems_iter() {
                    batch.add(&msg, MsgType::Add);
                }
            }
        }

        // Finalize and send batch
        let finalized = batch.finalize();
        self.send_batch(&finalized)?;

        Ok(true)
    }

    /// Send a finalized batch to netfilter via netlink socket.
    fn send_batch(&mut self, batch: &nftnl::FinalizedBatch) -> Result<(), Box<dyn Error>> {
        let portid = self.socket.portid();

        // Send entire batch at once
        self.socket.send_all(batch)?;

        let mut buffer = vec![0u8; nftnl::nft_nlmsg_maxsize() as usize];
        let mut expected_seqs = batch.sequence_numbers();

        // Process acknowledgment messages from netfilter
        while !expected_seqs.is_empty() {
            for message in self.socket.recv(&mut buffer[..])? {
                let message = message?;
                let expected_seq = expected_seqs.next().expect("Unexpected ACK");
                // Validate sequence number and check for error messages
                mnl::cb_run(message, expected_seq, portid)?;
            }
        }

        Ok(())
    }
}
