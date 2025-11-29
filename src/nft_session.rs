use std::{borrow::Cow, error::Error, net::IpAddr};

use log::debug;
use nftables::{
    batch::Batch,
    expr,
    helper,
    schema::{Element, NfListObject},
    types::NfFamily,
};

/// Wrapper around nftables for managing IP ban sets with timeouts.
/// Mimics the API of ipset::Session<HashIp> for easier migration.
pub struct NftSession {
    table: String,
    set: String,
    family: NfFamily,
    dry_run: bool,
}

impl NftSession {
    /// Create a new nftables session for a specific set.
    ///
    /// # Arguments
    /// * `table` - The nftables table name (e.g., "leroyjenkins")
    /// * `set` - The set name within the table (e.g., "leroy4" or "leroy6")
    /// * `family` - The IP family (NfFamily::IP or NfFamily::IP6)
    pub fn new(table: String, set: String, family: NfFamily) -> Self {
        NftSession {
            table,
            set,
            family,
            dry_run: false,
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
        let set_exists = ruleset
            .objects
            .iter()
            .any(|obj| match obj {
                nftables::schema::NfObject::ListObject(NfListObject::Set(set)) => {
                    set.family == self.family
                        && set.table == self.table
                        && set.name == self.set
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
    ///
    /// # Arguments
    /// * `ip` - The IP address to ban
    /// * `timeout` - The timeout in seconds
    ///
    /// # Returns
    /// * `Ok(true)` - Element was added (we always return true since nftables doesn't report duplicates)
    /// * `Err(_)` - Failed to add element
    pub fn add(&self, ip: IpAddr, timeout: u32) -> Result<bool, Box<dyn Error>> {
        if self.dry_run {
            debug!("Dry-run: would add {} to set {} with timeout {}s", ip, self.set, timeout);
            return Ok(true);
        }

        let mut batch = Batch::new();

        // Create the element with timeout using nftables Expression types
        let elem = Element {
            family: self.family.clone(),
            table: Cow::Borrowed(&self.table),
            name: Cow::Borrowed(&self.set),
            elem: Cow::Owned(vec![
                expr::Expression::Named(expr::NamedExpression::Elem(expr::Elem {
                    val: Box::new(expr::Expression::String(ip.to_string().into())),
                    timeout: Some(timeout),
                    expires: None,
                    comment: None,
                    counter: None,
                }))
            ]),
        };

        batch.add(NfListObject::Element(elem));

        let ruleset = batch.to_nftables();
        helper::apply_ruleset(&ruleset)?;

        Ok(true)
    }
}
