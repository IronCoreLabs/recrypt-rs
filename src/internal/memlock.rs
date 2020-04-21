use cfg_if::cfg_if;

// The memlock code below is inspired by the secstr project
// https://github.com/myfreeweb/secstr
// Which was generously released into the public domain.
// The functions were modified to deal with structs rather than slices.
cfg_if! {
    //If we are targeting wasm or not unix/windows we need to set the lock and unlock functions
    //to empty. This will also happen if you've enabled "disable_memlock" feature flag
    if #[cfg(any(feature="disable_memlock", target_arch = "wasm32", all(not(unix), not(windows))))] {
        #[inline(always)]
        pub fn mlock<T: Sized>(_cont: &T) {}
        #[inline(always)]
        pub fn munlock<T: Sized>(_cont: &T) {}
        #[inline(always)]
        pub fn mlock_slice<T: Sized>(_cont: &[T]) {}
        #[inline(always)]
        pub fn munlock_slice<T: Sized>(_cont: &[T]) {}
    } else if #[cfg(unix)]{
        pub fn mlock<T: Sized>(cont: &T) {
            let ptr: *const T = cont;
            let size = std::mem::size_of::<T>();
            unsafe {
                libc::mlock(ptr as *mut libc::c_void, size);
                #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
                libc::madvise(ptr, size, libc::MADV_NOCORE);
                #[cfg(target_os = "linux")]
                libc::madvise(ptr as *mut libc::c_void, size, libc::MADV_DONTDUMP);
            }
        }
        pub fn munlock<T: Sized>(cont: &T) {
            let ptr: *const T = cont;
            let size = std::mem::size_of::<T>();
            unsafe {
                libc::munlock(ptr as *mut libc::c_void, size);
                #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
                libc::madvise(ptr, size, libc::MADV_CORE);
                #[cfg(target_os = "linux")]
                libc::madvise(ptr as *mut libc::c_void, size, libc::MADV_DODUMP);
            }
        }

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
    } else if #[cfg(windows)]{
        pub fn mlock<T: Sized>(cont: &T) {
            let addr: *const T = cont;
            let len = std::mem::size_of::<T>();
            unsafe {
                ::winapi::um::memoryapi::VirtualLock(
                    addr as ::winapi::shared::minwindef::LPVOID,
                    len as ::winapi::shared::basetsd::SIZE_T,
                );
            }
        }
        pub fn munlock<T: Sized>(cont: &T) {
            let addr: *const T = cont;
            let len = std::mem::size_of::<T>();
            unsafe {
                ::winapi::um::memoryapi::VirtualUnlock(
                    addr as ::winapi::shared::minwindef::LPVOID,
                    len as ::winapi::shared::basetsd::SIZE_T,
                );
            }
        }
        pub fn mlock_slice<T: Sized>(cont: &[T]) {
            unsafe {
                let addr = cont.as_ptr() as ::winapi::shared::minwindef::LPVOID;
                let len = size_of_slice(cont);
                ::winapi::um::memoryapi::VirtualLock(addr, len as ::winapi::shared::basetsd::SIZE_T);
            }
        }
        pub fn munlock_slice<T: Sized>(cont: &[T]) {
            unsafe {
                let addr = cont.as_ptr() as ::winapi::shared::minwindef::LPVOID;
                let len = size_of_slice(cont);
                ::winapi::um::memoryapi::VirtualUnlock(
                    addr as ::winapi::shared::minwindef::LPVOID,
                    len as ::winapi::shared::basetsd::SIZE_T,
                );
            }
        }
    }
}

//This allow is here so we don't get unused code warnings if the disable_memprotect is set.
#[allow(dead_code)]
fn size_of_slice<T: Sized>(slice: &[T]) -> usize {
    slice.len() * std::mem::size_of::<T>()
}
