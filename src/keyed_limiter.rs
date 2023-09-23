use std::{cmp::max, collections::HashMap, hash::Hash};

use governor::{
    clock::{DefaultClock, QuantaInstant},
    state::keyed::HashMapStateStore,
    NotUntil, Quota, RateLimiter,
};
use log::debug;
use parking_lot::Mutex;

pub struct KeyedLimiter<K>
where
    K: Hash + Eq + Clone,
{
    rate_limiter: RateLimiter<K, HashMapStateStore<K>, DefaultClock>,
    initial_capacity: usize,
    next_gc_len: usize,
}

impl<K> KeyedLimiter<K>
where
    K: Hash + Eq + Clone,
{
    pub fn new(quota: Quota, initial_capacity: usize) -> KeyedLimiter<K> {
        KeyedLimiter {
            rate_limiter: RateLimiter::new(
                quota,
                Mutex::new(HashMap::with_capacity(initial_capacity)),
                &DefaultClock::default(),
            ),
            initial_capacity,
            next_gc_len: initial_capacity,
        }
    }

    pub fn check_key(&mut self, key: &K) -> Result<(), NotUntil<QuantaInstant>> {
        self.rate_limiter.check_key(key)
    }

    pub fn maybe_gc(&mut self) {
        if self.rate_limiter.len() >= self.next_gc_len {
            let old_len = self.rate_limiter.len();
            self.rate_limiter.retain_recent();
            let new_len = self.rate_limiter.len();

            debug!("Garbage collected rate limiter table: {old_len} -> {new_len} entries");

            self.next_gc_len = max(self.initial_capacity, new_len * 2);
        }
    }
}
