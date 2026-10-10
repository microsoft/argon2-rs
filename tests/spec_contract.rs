use argon2_verus::{Algorithm, Argon2, Backend, Params, Version};

#[test]
fn memory_geometry_preserves_original_parameter_in_initial_hash() {
    for lanes in 1..=4 {
        let memory = 8 * lanes;
        let mut rounded = [0; 32];
        let mut unrounded = [0; 32];
        for (memory_kib, out) in [(memory, &mut rounded), (memory + 1, &mut unrounded)] {
            Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params { parallelism: lanes, memory_kib, iterations: 2 },
            )
            .with_backend(Backend::Scalar)
            .hash_password_into(b"password", b"saltsalt", out)
            .unwrap();
        }
        assert_ne!(rounded, unrounded, "H0 must include requested memory, not rounded memory");
    }
}

#[test]
fn rejected_parameters_leave_output_unchanged() {
    for params in [
        Params { parallelism: 0, memory_kib: 8, iterations: 1 },
        Params { parallelism: 1 << 24, memory_kib: u32::MAX, iterations: 1 },
        Params { parallelism: 2, memory_kib: 15, iterations: 1 },
        Params { parallelism: 1, memory_kib: 8, iterations: 0 },
    ] {
        let mut out = [0xa5; 32];
        assert!(Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"password", b"saltsalt", &mut out)
            .is_err());
        assert_eq!(out, [0xa5; 32]);
    }
}
