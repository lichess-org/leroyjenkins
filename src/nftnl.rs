use std::{
    ffi::{c_char, c_void, CStr},
    marker::PhantomData,
    mem,
    net::IpAddr,
    ptr::NonNull,
    slice,
    time::Duration,
};

use mnl_sys::{
    mnl_nlmsg_batch, mnl_nlmsg_batch_current, mnl_nlmsg_batch_head, mnl_nlmsg_batch_next,
    mnl_nlmsg_batch_reset, mnl_nlmsg_batch_size, mnl_nlmsg_batch_start, mnl_nlmsg_batch_stop,
};
use nftnl_sys::{
    nftnl_batch_begin, nftnl_batch_end, nftnl_nlmsg_build_hdr, nftnl_set, nftnl_set_alloc,
    nftnl_set_elem, nftnl_set_elem_add, nftnl_set_elem_alloc, nftnl_set_elem_free,
    nftnl_set_elem_set, nftnl_set_elem_set_u64, nftnl_set_elems_nlmsg_build_payload,
    nftnl_set_free, nftnl_set_set_str,
};

pub struct NftnlSet {
    inner: NonNull<nftnl_set>,
}

impl NftnlSet {
    pub fn new() -> NftnlSet {
        NftnlSet {
            inner: NonNull::new(unsafe { nftnl_set_alloc() }).expect("nftnl_set_alloc"),
        }
    }

    pub fn set_table(&mut self, table: &CStr) {
        assert_eq!(
            unsafe {
                nftnl_set_set_str(
                    self.inner.as_ptr(),
                    nftnl_sys::NFTNL_SET_TABLE as u16,
                    table.as_ptr(),
                )
            },
            0
        );
    }

    pub fn set_name(&mut self, name: &CStr) {
        assert_eq!(
            unsafe {
                nftnl_set_set_str(
                    self.inner.as_ptr(),
                    nftnl_sys::NFTNL_SET_NAME as u16,
                    name.as_ptr(),
                )
            },
            0
        );
    }

    pub fn add(&mut self, elem: NftnlSetElem) {
        unsafe {
            nftnl_set_elem_add(self.inner.as_ptr(), elem.inner.as_ptr());
        }
        mem::forget(elem);
    }
}

impl Default for NftnlSet {
    fn default() -> Self {
        NftnlSet::new()
    }
}

impl Drop for NftnlSet {
    fn drop(&mut self) {
        unsafe { nftnl_set_free(self.inner.as_ptr()) };
    }
}

pub struct NftnlSetElem {
    inner: NonNull<nftnl_set_elem>,
}

impl NftnlSetElem {
    pub fn new() -> NftnlSetElem {
        NftnlSetElem {
            inner: NonNull::new(unsafe { nftnl_set_elem_alloc() }).expect("nftnl_set_elem_alloc"),
        }
    }

    pub fn set_key(&mut self, key: IpAddr) {
        let octets = key.as_octets();
        assert_eq!(
            unsafe {
                nftnl_set_elem_set(
                    self.inner.as_ptr(),
                    nftnl_sys::NFTNL_SET_ELEM_KEY as u16,
                    octets.as_ptr().cast::<c_void>(),
                    octets.len() as u32,
                )
            },
            0
        );
    }

    pub fn set_timeout(&mut self, duration: Duration) {
        unsafe {
            nftnl_set_elem_set_u64(
                self.inner.as_ptr(),
                nftnl_sys::NFTNL_SET_ELEM_TIMEOUT as u16,
                duration.as_millis().try_into().unwrap_or(u64::MAX),
            )
        }
    }
}

impl Default for NftnlSetElem {
    fn default() -> Self {
        NftnlSetElem::new()
    }
}

impl Drop for NftnlSetElem {
    fn drop(&mut self) {
        unsafe { nftnl_set_elem_free(self.inner.as_ptr()) };
    }
}

#[derive(Copy, Clone)]
pub struct Seq(pub u32);

impl Seq {
    #[must_use]
    pub fn inc(self) -> Self {
        Seq(self.0.wrapping_add(1))
    }
}

pub struct NlmsgBatch<'a> {
    batch: NonNull<mnl_nlmsg_batch>,
    seq: Seq,
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> NlmsgBatch<'a> {
    pub fn new(buffer: &mut [u8], seq: Seq) -> NlmsgBatch<'_> {
        NlmsgBatch {
            batch: unsafe {
                NonNull::new(mnl_nlmsg_batch_start(
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len(),
                ))
                .expect("mnl_nlmsg_batch_start")
            },
            seq,
            _marker: PhantomData,
        }
    }

    pub fn begin(&mut self) {
        self.seq = self.seq.inc();
        unsafe {
            nftnl_batch_begin(
                mnl_nlmsg_batch_current(self.batch.as_ptr()).cast::<c_char>(),
                self.seq.0,
            );
            assert!(
                mnl_nlmsg_batch_next(self.batch.as_ptr()),
                "mnl_nlmsg_batch_next after begin"
            );
        }
    }

    pub fn set_elems(&mut self, msg_type: u16, family: u16, flags: u16, set: &NftnlSet) {
        self.seq = self.seq.inc();
        let header = unsafe {
            nftnl_nlmsg_build_hdr(
                mnl_nlmsg_batch_current(self.batch.as_ptr()).cast::<c_char>(),
                msg_type,
                family,
                flags,
                self.seq.0,
            )
        };

        unsafe {
            nftnl_set_elems_nlmsg_build_payload(header, set.inner.as_ptr());
            assert!(
                mnl_nlmsg_batch_next(self.batch.as_ptr()),
                "mnl_nlmsg_batch_next after set_elems"
            );
        }
    }

    pub fn end(&mut self) {
        self.seq = self.seq.inc();
        unsafe {
            nftnl_batch_end(
                mnl_nlmsg_batch_current(self.batch.as_ptr()).cast::<c_char>(),
                self.seq.0,
            );
            assert!(
                mnl_nlmsg_batch_next(self.batch.as_ptr()),
                "mnl_nlmsg_batch_next after end"
            );
        }
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        unsafe {
            slice::from_raw_parts(
                mnl_nlmsg_batch_head(self.batch.as_ptr()).cast::<u8>(),
                mnl_nlmsg_batch_size(self.batch.as_ptr()),
            )
        }
    }

    pub fn seq(&self) -> Seq {
        self.seq
    }
}

impl Drop for NlmsgBatch<'_> {
    fn drop(&mut self) {
        unsafe {
            mnl_nlmsg_batch_stop(self.batch.as_ptr());
        }
    }
}
