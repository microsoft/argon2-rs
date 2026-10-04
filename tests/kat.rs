//! Known-answer tests from RFC 9106 Section 5 (the official IETF test
//! vectors), covering all three Argon2 variants at version 0x13.

use argon2_verus::{Algorithm, Argon2, Backend, Params, Version};

const PASSWORD: [u8; 32] = [0x01; 32];
const SALT: [u8; 16] = [0x02; 16];
const SECRET: [u8; 8] = [0x03; 8];
const AD: [u8; 12] = [0x04; 12];

/// Every backend this CPU can run; the KATs must hold for each of them.
fn backends() -> Vec<Backend> {
    let all = [
        Backend::Scalar,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Backend::Sse2,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Backend::Ssse3,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Backend::Avx2,
    ];
    all.into_iter().filter(|b| b.is_available()).collect()
}

fn run_with(algorithm: Algorithm, backend: Backend) -> [u8; 32] {
    let params = Params { parallelism: 4, memory_kib: 32, iterations: 3 };
    let argon2 = Argon2::new(algorithm, Version::V0x13, params).with_backend(backend);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into_with_secret(&PASSWORD, &SALT, &SECRET, &AD, &mut out)
        .expect("hash should succeed with valid RFC 9106 test-vector params");
    out
}

fn run(algorithm: Algorithm) -> [u8; 32] {
    let outputs: Vec<_> = backends().into_iter().map(|b| (b, run_with(algorithm, b))).collect();
    for (b, o) in &outputs {
        assert_eq!(*o, outputs[0].1, "{b:?} disagrees with {:?}", outputs[0].0);
    }
    outputs[0].1
}

#[test]
fn rfc9106_argon2d() {
    let expected: [u8; 32] = [
        0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42,
        0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe,
        0x4a, 0xcb,
    ];
    assert_eq!(run(Algorithm::Argon2d), expected);
}

#[test]
fn rfc9106_argon2i() {
    let expected: [u8; 32] = [
        0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa, 0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd,
        0xa1, 0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2, 0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b,
        0x6c, 0xe8,
    ];
    assert_eq!(run(Algorithm::Argon2i), expected);
}

#[test]
fn rfc9106_argon2id() {
    let expected: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53,
        0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01,
        0xe6, 0x59,
    ];
    assert_eq!(run(Algorithm::Argon2id), expected);
}

/// Whole-hash agreement across backends over parameters the KATs don't hit:
/// one and several lanes, both versions, all variants, memory sizes that are
/// not multiples of 4p, several passes, and empty/long passwords.
#[test]
fn all_backends_agree_across_parameters() {
    let backends = backends();
    let long_password = vec![0xA5u8; 300];
    for algorithm in [Algorithm::Argon2d, Algorithm::Argon2i, Algorithm::Argon2id] {
        for version in [Version::V0x10, Version::V0x13] {
            for (parallelism, memory_kib, iterations) in
                [(1, 8, 1), (1, 64, 3), (2, 67, 2), (3, 100, 1), (4, 256, 2), (1, 1024, 2)]
            {
                for password in [&b""[..], b"password", &long_password] {
                    let params = Params { parallelism, memory_kib, iterations };
                    let mut expected = [0u8; 32];
                    for (i, &backend) in backends.iter().enumerate() {
                        let mut out = [0u8; 32];
                        Argon2::new(algorithm, version, params)
                            .with_backend(backend)
                            .hash_password_into(password, &SALT, &mut out)
                            .unwrap();
                        if i == 0 {
                            expected = out;
                        } else {
                            assert_eq!(
                                out, expected,
                                "{backend:?} {algorithm:?} {version:?} {params:?}"
                            );
                        }
                    }
                }
            }
        }
    }
}
