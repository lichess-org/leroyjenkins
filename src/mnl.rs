use std::{
    alloc,
    ffi::{c_uint, c_void},
    io, mem,
    ptr::{self, NonNull},
};

use mnl_sys::{
    MNL_SOCKET_AUTOPID, mnl_cb_run, mnl_socket, mnl_socket_bind, mnl_socket_close,
    mnl_socket_get_portid, mnl_socket_open2, mnl_socket_recvfrom, mnl_socket_sendto,
};

use crate::seq::Seq;

pub struct MnlSocket {
    inner: NonNull<mnl_socket>,
}

impl MnlSocket {
    pub fn new_netfilter() -> io::Result<Self> {
        let mut socket = Self::open_netfilter()?;
        socket.bind()?;
        Ok(socket)
    }

    fn open_netfilter() -> io::Result<Self> {
        // Note: Sending/receiving for netfilter sockets is synchronous
        // even with SOCK_NONBLOCK. It merely makes mnl_socket_recvfrom() not
        // block if no further response is available.
        Ok(MnlSocket {
            inner: NonNull::new(unsafe {
                mnl_socket_open2(libc::NETLINK_NETFILTER, libc::SOCK_NONBLOCK)
            })
            .ok_or_else(io::Error::last_os_error)?,
        })
    }

    fn bind(&mut self) -> io::Result<()> {
        if unsafe { mnl_socket_bind(self.inner.as_ptr(), 0, MNL_SOCKET_AUTOPID) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        let ret = unsafe {
            mnl_socket_sendto(
                self.inner.as_ptr(),
                data.as_ptr().cast::<c_void>(),
                data.len(),
            )
        };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        if ret as usize != data.len() {
            return Err(io::Error::other("partial write for mnl_socket_sendto"));
        }
        Ok(())
    }

    fn recv_raw(&mut self, buffer: &mut MnlReceiveBuffer) -> io::Result<usize> {
        let ret = unsafe {
            mnl_socket_recvfrom(
                self.inner.as_ptr(),
                buffer.as_mut_ptr().cast::<c_void>(),
                buffer.len(),
            )
        };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(ret as usize)
    }

    pub fn recv_and_validate(
        &mut self,
        buffer: &mut MnlReceiveBuffer,
        seq: Option<Seq>,
        port_id: MnlPortId,
    ) -> io::Result<usize> {
        // Do recv as part of the safe wrapper, so that libmnl bug
        // https://rustsec.org/advisories/RUSTSEC-2025-0142.html does not
        // lead to unsoundness.
        let num_bytes = self.recv_raw(buffer)?;
        let ret = unsafe {
            mnl_cb_run(
                buffer.as_ptr().cast::<c_void>(),
                num_bytes,
                seq.map(u32::from).unwrap_or_default(),
                port_id.0,
                None,
                ptr::null_mut(),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(num_bytes)
    }

    pub fn port_id(&self) -> MnlPortId {
        MnlPortId(unsafe { mnl_socket_get_portid(self.inner.as_ptr()) })
    }
}

impl Drop for MnlSocket {
    fn drop(&mut self) {
        unsafe { mnl_socket_close(self.inner.as_ptr()) };
    }
}

#[derive(Copy, Clone)]
pub struct MnlPortId(pub c_uint);

pub struct MnlReceiveBuffer {
    ptr: *mut u8,
    layout: alloc::Layout,
}

impl MnlReceiveBuffer {
    pub fn new(size: usize) -> Self {
        let layout = alloc::Layout::from_size_align(
            size,
            mem::align_of::<libc::nlmsghdr>(), // NLMSG_ALIGNTO
        )
        .expect("valid layout");

        let ptr = unsafe { alloc::alloc(layout) };
        if ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }

        MnlReceiveBuffer { ptr, layout }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    pub fn len(&self) -> usize {
        self.layout.size()
    }
}

impl Drop for MnlReceiveBuffer {
    fn drop(&mut self) {
        unsafe { alloc::dealloc(self.ptr, self.layout) };
    }
}
