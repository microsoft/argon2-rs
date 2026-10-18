use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) struct Bytes<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> Drop for Bytes<N> {
    fn drop(&mut self) {
        bytes(&mut self.0);
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) struct Words<const N: usize>(pub(crate) [u64; N]);

impl<const N: usize> Drop for Words<N> {
    fn drop(&mut self) {
        words(&mut self.0);
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) struct ByteVec(pub(crate) Vec<u8>);

#[cfg_attr(verus_keep_ghost, cfg_eval)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
impl ByteVec {
    #[cfg_attr(verus_keep_ghost, verus_spec(result =>
        ensures result@ == self.0@,
    ))]
    pub(crate) fn into_inner(self) -> Vec<u8> {
        let mut owner = self;
        let mut output = Vec::new();
        core::mem::swap(&mut owner.0, &mut output);
        output
    }
}

impl Drop for ByteVec {
    fn drop(&mut self) {
        bytes(&mut self.0);
    }
}

pub(crate) fn bytes(values: &mut [u8]) {
    fill(values, 0);
}

pub(crate) fn words(values: &mut [u64]) {
    fill(values, 0);
}

pub(crate) fn fill<T: Copy>(values: &mut [T], zero: T) {
    #[cfg(test)]
    let count = values.len();
    for value in values {
        // SAFETY: each pointer is derived from a live, exclusively borrowed element.
        unsafe { core::ptr::write_volatile(value, zero) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPES.with(|wipes| {
        if let Some(events) = wipes.borrow_mut().as_mut() {
            events.push((count, core::mem::size_of::<T>()));
        }
    });
}

#[cfg(test)]
std::thread_local! {
    static WIPES: std::cell::RefCell<Option<Vec<(usize, usize)>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn observe(action: impl FnOnce()) -> (std::thread::Result<()>, Vec<(usize, usize)>) {
    WIPES.with(|wipes| {
        assert!(wipes.borrow().is_none());
        *wipes.borrow_mut() = Some(Vec::with_capacity(4096));
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
    let events = WIPES.with(|wipes| wipes.borrow_mut().take().unwrap());
    (result, events)
}

#[cfg(test)]
mod tests {
    #[test]
    fn overwrites_live_storage_and_accepts_empty_slices() {
        let mut bytes = [0xa5; 31];
        let mut words = [u64::MAX; 17];
        super::bytes(&mut bytes);
        super::words(&mut words);
        assert_eq!(bytes, [0; 31]);
        assert_eq!(words, [0; 17]);
        super::bytes(&mut []);
        super::words(&mut []);
    }

    #[test]
    fn owners_wipe_on_return_and_unwind() {
        for panic in [false, true] {
            if panic && !cfg!(panic = "unwind") {
                eprintln!("skipping unwinding case: this build aborts on panic");
                continue;
            }
            let (result, events) = super::observe(|| {
                let _bytes = super::Bytes([0xa5; 31]);
                let _words = super::Words([u64::MAX; 17]);
                let _vec = super::ByteVec(vec![0xa5; 19]);
                assert!(!panic, "exercise unwinding cleanup");
            });
            assert_eq!(result.is_err(), panic);
            assert_eq!(events, [(19, 1), (17, 8), (31, 1)]);
        }
    }

    #[test]
    fn owners_wipe_on_error_return() {
        fn fail() -> Result<(), &'static str> {
            let _h0 = super::Bytes([0xa5; 64]);
            let _block = super::Words([u64::MAX; 128]);
            Err("exercise early-return cleanup")?;
            Ok(())
        }
        let (result, events) = super::observe(|| {
            assert_eq!(fail(), Err("exercise early-return cleanup"));
        });
        result.unwrap();
        assert_eq!(events, [(128, 8), (64, 1)]);
    }

    #[test]
    fn transferring_output_preserves_bytes_and_wipes_only_empty_owner() {
        let (result, events) = super::observe(|| {
            let output = super::ByteVec(vec![0xa5; 19]).into_inner();
            assert_eq!(output, [0xa5; 19]);
        });
        result.unwrap();
        assert_eq!(events, [(0, 1)]);
    }

    #[test]
    fn hashing_wipes_temporary_owners_on_each_backend() {
        use crate::core_backend::Backend;
        use crate::{Algorithm, Params, Version};
        let mut backends = vec![Backend::Scalar];
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        backends.extend([Backend::Sse2, Backend::Ssse3, Backend::Avx2]);
        for backend in backends {
            if !backend.is_available() {
                continue;
            }
            let (result, events) = super::observe(|| {
                let mut tag = [0; 32];
                crate::core_impl::hash_into_with_backend(
                    backend,
                    Algorithm::Argon2id,
                    Version::V0x13,
                    &Params { parallelism: 1, memory_kib: 8, iterations: 1 },
                    b"password",
                    b"saltsalt",
                    &[],
                    &[],
                    &mut tag,
                )
                .unwrap();
                assert_ne!(tag, [0; 32]);
            });
            result.unwrap();
            for event in [(64, 1), (72, 1), (128, 1), (16, 8), (128, 8), (1024, 1), (32, 1)] {
                assert!(events.contains(&event), "{backend:?}: missing wipe {event:?}");
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            match backend {
                Backend::Sse2 | Backend::Ssse3 => assert!(events.contains(&(64, 16))),
                Backend::Avx2 => assert!(events.contains(&(32, 32))),
                Backend::Scalar => {}
            }
        }
    }
}
