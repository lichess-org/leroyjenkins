use std::{
    cell::{Cell, RefCell},
    cmp::max,
    collections::HashMap,
    hash::{BuildHasher, Hash},
    num::NonZeroU64,
};

use governor::{
    clock::{DefaultClock, QuantaInstant},
    nanos::Nanos,
    state::{keyed::ShrinkableKeyedStateStore, StateStore},
    NotUntil, Quota, RateLimiter,
};
use log::debug;

#[derive(Default)]
struct UnsyncInMemoryState {
    value: Cell<u64>,
}

impl UnsyncInMemoryState {
    fn measure_and_replace_one<T, F, E>(&self, mut f: F) -> Result<T, E>
    where
        F: FnMut(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        let prev = self.value.get();
        let (payload, next) = f(NonZeroU64::new(prev).map(|n| n.get().into()))?;
        self.value.set(next.into());
        Ok(payload)
    }

    fn is_older_than(&self, nanos: Nanos) -> bool {
        self.value.get() <= nanos.into()
    }
}

struct UnsyncHashMapStateStore<K, S> {
    buckets: RefCell<HashMap<K, UnsyncInMemoryState, S>>,
}

impl<K, S> UnsyncHashMapStateStore<K, S> {
    fn with_capacity_and_hasher(capacity: usize, hasher: S) -> UnsyncHashMapStateStore<K, S> {
        UnsyncHashMapStateStore {
            buckets: RefCell::new(HashMap::with_capacity_and_hasher(capacity, hasher)),
        }
    }
}

impl<K, S> StateStore for UnsyncHashMapStateStore<K, S>
where
    K: Hash + Eq + Clone,
    S: BuildHasher,
{
    type Key = K;

    fn measure_and_replace<T, F, E>(&self, key: &K, f: F) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        let mut buckets = self.buckets.borrow_mut();
        if let Some(v) = buckets.get(key) {
            return v.measure_and_replace_one(f);
        }
        let entry = buckets.entry(key.clone()).or_default();
        entry.measure_and_replace_one(f)
    }
}

impl<K, S> ShrinkableKeyedStateStore<K> for UnsyncHashMapStateStore<K, S>
where
    K: Hash + Eq + Clone,
    S: BuildHasher,
{
    fn retain_recent(&self, drop_below: Nanos) {
        self.buckets
            .borrow_mut()
            .retain(|_, v| !v.is_older_than(drop_below));
    }

    fn shrink_to_fit(&self) {
        self.buckets.borrow_mut().shrink_to_fit();
    }

    fn len(&self) -> usize {
        self.buckets.borrow().len()
    }

    fn is_empty(&self) -> bool {
        self.buckets.borrow().is_empty()
    }
}

pub struct KeyedLimiter<K, S>
where
    K: Hash + Eq + Clone,
    S: BuildHasher,
{
    rate_limiter: RateLimiter<K, UnsyncHashMapStateStore<K, S>, DefaultClock>,
    initial_capacity: usize,
    next_gc_len: usize,
}

impl<K, S> KeyedLimiter<K, S>
where
    K: Hash + Eq + Clone,
    S: BuildHasher,
{
    pub fn new(quota: Quota, initial_capacity: usize, hasher: S) -> KeyedLimiter<K, S> {
        KeyedLimiter {
            rate_limiter: RateLimiter::new(
                quota,
                UnsyncHashMapStateStore::with_capacity_and_hasher(initial_capacity, hasher),
                &DefaultClock::default(),
            ),
            initial_capacity,
            next_gc_len: initial_capacity,
        }
    }

    pub fn check_key(&mut self, key: &K) -> Result<(), NotUntil<QuantaInstant>> {
        self.maybe_gc();
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
