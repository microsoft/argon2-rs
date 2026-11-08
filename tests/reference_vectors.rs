//! Independent whole-hash vectors; provenance and regeneration are in reference/README.md.

use argon2_verus::{Algorithm, Argon2, Backend, Params, Version};

#[test]
fn pinned_reference_vectors_match_every_available_backend() {
    let backends = [
        Backend::Scalar,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Backend::Sse2,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Backend::Ssse3,
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        Backend::Avx2,
    ];
    let mut cases = 0;
    for (index, line) in include_str!("reference/argon2-20190702.tsv").lines().enumerate() {
        if line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 9, "invalid fixture line {}", index + 1);
        let number = |column: usize| fields[column].parse::<u32>().unwrap();
        let algorithm = match number(0) {
            0 => Algorithm::Argon2d,
            1 => Algorithm::Argon2i,
            2 => Algorithm::Argon2id,
            other => panic!("invalid fixture algorithm {other}"),
        };
        let version = match number(1) {
            16 => Version::V0x10,
            19 => Version::V0x13,
            other => panic!("invalid fixture version {other}"),
        };
        let params =
            Params { parallelism: number(2), memory_kib: number(3), iterations: number(4) };
        assert!(params.parallelism <= 4 && params.memory_kib <= 256 && params.iterations <= 3);
        assert!(number(5) <= 300 && number(6) <= 8 && number(7) <= 12);
        let password = vec![1; number(5) as usize];
        let salt = [2; 16];
        let secret = vec![3; number(6) as usize];
        let ad = vec![4; number(7) as usize];
        let hex = fields[8];
        assert!(hex.is_ascii() && hex.len() % 2 == 0);
        let expected: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap())
            .collect();
        assert!([4, 16, 32, 63, 64, 65, 96].contains(&expected.len()));
        for backend in backends.into_iter().filter(|backend| backend.is_available()) {
            let mut out = vec![0; expected.len()];
            Argon2::new(algorithm, version, params)
                .with_backend(backend)
                .hash_password_into_with_secret(&password, &salt, &secret, &ad, &mut out)
                .unwrap();
            assert_eq!(out, expected, "fixture line {} with {backend:?}", index + 1);
        }
        cases += 1;
    }
    assert_eq!(cases, 168, "reference fixture must contain the complete matrix");
}
