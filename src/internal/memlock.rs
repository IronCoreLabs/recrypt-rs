// The memlock code below is inspired by the secstr project
// https://github.com/myfreeweb/secstr
// Which was generously released into the public domain.
// The functions were modified to deal with structs rather than slices.

#[cfg(unix)]
extern crate libc;

#[cfg(unix)]
pub fn mlock<T: Sized>(cont: &T) {
  let ptr: *const T = cont;
  let size = std::mem::size_of::<T>();
  unsafe {
    libc::mlock(ptr as *mut libc::c_void, size);
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    libc::madvise(ptr, size, libc::MADV_NOCORE);
    #[cfg(target_os = "linux")]
    libc::madvise(ptr, size, libc::MADV_DONTDUMP);
  }
}

#[cfg(unix)]
pub fn munlock<T: Sized>(cont: &T) {
  let ptr: *const T = cont;
  let size = std::mem::size_of::<T>();
  unsafe {
    libc::munlock(ptr as *mut libc::c_void, size);
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    libc::madvise(ptr, size, libc::MADV_CORE);
    #[cfg(target_os = "linux")]
    libc::madvise(ptr, size, libc::MADV_DODUMP);
  }
}

#[cfg(not(unix))]
pub fn mlock<T: Sized>(cont: &T) {}

#[cfg(not(unix))]
pub fn munlock<T: Sized>(cont: &T) {}

#[cfg(not(unix))]
pub fn mlock<T: Sized>(cont: &T) {}

#[cfg(not(unix))]
pub fn munlock<T: Sized>(cont: &T) {}

fn size_of_slice<T: Sized>(slice: &[T]) -> usize {
  slice.len() * std::mem::size_of::<T>()
}

#[cfg(unix)]
pub fn mlock_slice<T: Sized>(cont: &[T]) {
  let size = size_of_slice(cont);
  unsafe {
    let ptr = cont.as_ptr() as *mut libc::c_void;
    libc::mlock(ptr, size);
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    libc::madvise(ptr, size, libc::MADV_NOCORE);
    #[cfg(target_os = "linux")]
    libc::madvise(ptr, size, libc::MADV_DONTDUMP);
  }
}

#[cfg(unix)]
pub fn munlock_slice<T: Sized>(cont: &[T]) {
  let size = size_of_slice(cont);
  unsafe {
    let ptr = cont.as_ptr() as *mut libc::c_void;
    libc::munlock(ptr, size);
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    libc::madvise(ptr, size, libc::MADV_CORE);
    #[cfg(target_os = "linux")]
    libc::madvise(ptr, size, libc::MADV_DODUMP);
  }
}

#[cfg(not(unix))]
pub fn mlock_slice<T: Sized>(cont: &[T]) {}

#[cfg(not(unix))]
pub fn munlock_slice<T: Sized>(cont: &[T]) {}
