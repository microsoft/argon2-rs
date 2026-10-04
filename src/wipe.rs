use core::sync::atomic::{compiler_fence, Ordering};

pub(crate) fn bytes(values: &mut [u8]) {
    for value in values {
        // SAFETY: each pointer is derived from a live, exclusively borrowed element.
        unsafe { core::ptr::write_volatile(value, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub(crate) fn words(values: &mut [u64]) {
    for value in values {
        // SAFETY: each pointer is derived from a live, exclusively borrowed element.
        unsafe { core::ptr::write_volatile(value, 0) };
    }
    compiler_fence(Ordering::SeqCst);
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
}
