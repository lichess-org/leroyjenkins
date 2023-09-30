use std::{
    cell::{Cell, RefCell},
    cmp::max,
    hash::Hash,
    num::NonZeroU64,
};

use governor::{
    clock::{DefaultClock, QuantaInstant},
    nanos::Nanos,
    state::{keyed::ShrinkableKeyedStateStore, StateStore},
    NotUntil, Quota, RateLimiter,
};
use log::debug;
use rustc_hash::FxHashMap;

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

struct FxHashMapStateStore<K> {
    buckets: RefCell<FxHashMap<K, UnsyncInMemoryState>>,
}

impl<K> FxHashMapStateStore<K>
where
    K: Hash + Eq,
{
    fn with_capacity(initial_capacity: usize) -> FxHashMapStateStore<K> {
        FxHashMapStateStore {
            buckets: RefCell::new(FxHashMap::with_capacity_and_hasher(
                initial_capacity,
                Default::default(),
            )),
        }
    }
}

impl<K> StateStore for FxHashMapStateStore<K>
where
    K: Hash + Eq + Clone,
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

impl<K> ShrinkableKeyedStateStore<K> for FxHashMapStateStore<K>
where
    K: Hash + Eq + Clone,
{
    fn retain_recent(&self, drop_below: Nanos) {
        self.buckets
            .borrow_mut()
            .retain(|_, v| !v.is_older_than(drop_below));
    }

    fn shrink_to_fit(&self) {
        self.buckets.borrow_mut().shrink_to_fit()
    }

    fn len(&self) -> usize {
        self.buckets.borrow().len()
    }

    fn is_empty(&self) -> bool {
        self.buckets.borrow().is_empty()
    }
}

pub struct KeyedLimiter<K>
where
    K: Hash + Eq + Clone,
{
    rate_limiter: RateLimiter<K, FxHashMapStateStore<K>, DefaultClock>,
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
                FxHashMapStateStore::with_capacity(initial_capacity),
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
