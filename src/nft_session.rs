use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    net::IpAddr,
    time::{Duration, Instant},
};

use log::{debug, info};
use nftables::{
    batch::Batch,
    expr, helper,
    schema::{Element, NfListObject},
    types::NfFamily,
};

/// Wrapper around nftables for managing IP ban sets with timeouts.
/// Mimics the API of ipset::Session<HashIp> for easier migration.
/// Implements batching to reduce syscalls.
pub struct NftSession {
    table: String,
    set: String,
    family: NfFamily,
    dry_run: bool,

    // Batching state
    pending_ips: Vec<(IpAddr, u32)>,
    last_flush: Instant,
    batch_size: usize,
    batch_timeout: Duration,
}

impl NftSession {
    /// Create a new nftables session for a specific set.
    ///
    /// # Arguments
    /// * `table` - The nftables table name (e.g., "leroyjenkins")
    /// * `set` - The set name within the table (e.g., "leroy4" or "leroy6")
    /// * `family` - The IP family (NfFamily::IP or NfFamily::IP6)
    /// * `batch_size` - Max IPs to batch before flush
    /// * `batch_timeout` - Max time to wait before flush
    pub fn new(
        table: String,
        set: String,
        family: NfFamily,
        batch_size: usize,
        batch_timeout: Duration,
    ) -> Self {
        NftSession {
            table,
            set,
            family,
            dry_run: false,
            pending_ips: Vec::with_capacity(batch_size),
            last_flush: Instant::now(),
            batch_size,
            batch_timeout,
        }
    }

    /// Set dry-run mode. When enabled, operations are logged but not applied.
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    /// Test if the set exists by attempting to query it.
    /// This validates that the table and set are properly configured.
    ///
    /// # Arguments
    /// * `_ip` - Unused, kept for API compatibility with ipset::Session
    pub fn test(&self, _ip: IpAddr) -> Result<bool, Box<dyn Error>> {
        if self.dry_run {
            return Ok(true);
        }

        // Query the ruleset to check if our set exists
        let ruleset = helper::get_current_ruleset()?;

        // Look for our specific set in the ruleset
        let set_exists = ruleset.objects.iter().any(|obj| match obj {
            nftables::schema::NfObject::ListObject(NfListObject::Set(set)) => {
                set.family == self.family && set.table == self.table && set.name == self.set
            }
            _ => false,
        });

        if set_exists {
            Ok(true)
        } else {
            Err(format!(
                "Set {} does not exist in table {} (family {:?})",
                self.set, self.table, self.family
            )
            .into())
        }
    }

    /// Add an IP address to the set with a specific timeout.
    /// Uses batching to reduce syscalls - flushes when timeout expires OR batch_size reached.
    ///
    /// # Arguments
    /// * `ip` - The IP address to ban
    /// * `timeout` - The timeout in seconds
    ///
    /// # Returns
    /// * `Ok(true)` - Element was queued/added
    /// * `Err(_)` - Failed to flush batch
    pub fn add(&mut self, ip: IpAddr, timeout: u32) -> Result<bool, Box<dyn Error>> {
        if self.dry_run {
            debug!(
                "Dry-run: would add {} to set {} with timeout {}s",
                ip, self.set, timeout
            );
            return Ok(true);
        }

        // Flush if timeout expired OR batch size reached (check before adding)
        if !self.pending_ips.is_empty()
            && (self.last_flush.elapsed() >= self.batch_timeout
                || self.pending_ips.len() >= self.batch_size)
        {
            self.flush()?;
        }

        // Add to pending batch
        self.pending_ips.push((ip, timeout));

        Ok(true)
    }

    /// Flush all pending IPs to nftables in a single batch.
    /// Groups IPs by timeout since nftables requires same timeout per Element.
    fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        if self.pending_ips.is_empty() {
            return Ok(());
        }

        let total_ips = self.pending_ips.len();

        // Group IPs by timeout value
        let mut by_timeout: HashMap<u32, Vec<IpAddr>> = HashMap::new();
        for (ip, timeout) in self.pending_ips.drain(..) {
            by_timeout.entry(timeout).or_default().push(ip);
        }

        // Log batch flush with timeout distribution
        info!(
            target: "leroyjenkins",
            "Flushing batch of {} IPs to set {} ({}s since last flush):",
            total_ips,
            self.set,
            self.last_flush.elapsed().as_secs()
        );

        if total_ips < 5 {
            // Show individual IPs for small batches
            for (timeout, ips) in &by_timeout {
                let ip_list: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                info!(target: "leroyjenkins", "  - {}s timeout: {}", timeout, ip_list.join(", "));
            }
        } else {
            // Show counts only for large batches
            for (timeout, ips) in &by_timeout {
                info!(target: "leroyjenkins", "  - {}s timeout: {} IPs", timeout, ips.len());
            }
        }

        // Create batch with one Element per timeout group
        let mut batch = Batch::new();
        for (timeout, ips) in by_timeout {
            // Create Expression for each IP with its timeout
            let elem_exprs: Vec<expr::Expression> = ips
                .into_iter()
                .map(|ip| {
                    expr::Expression::Named(expr::NamedExpression::Elem(expr::Elem {
                        val: Box::new(expr::Expression::String(ip.to_string().into())),
                        timeout: Some(timeout),
                        expires: None,
                        comment: None,
                        counter: None,
                    }))
                })
                .collect();

            batch.add(NfListObject::Element(Element {
                family: self.family.clone(),
                table: Cow::Borrowed(&self.table),
                name: Cow::Borrowed(&self.set),
                elem: Cow::Owned(elem_exprs),
            }));
        }

        // Apply the batch
        let ruleset = batch.to_nftables();
        helper::apply_ruleset(&ruleset)?;

        self.last_flush = Instant::now();
        Ok(())
    }

    /// Flush pending IPs on shutdown.
    /// Public method to allow explicit flushing before process exit.
    pub fn flush_on_shutdown(&mut self) -> Result<(), Box<dyn Error>> {
        self.flush()
    }
}
