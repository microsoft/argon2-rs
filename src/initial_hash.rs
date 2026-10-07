#[cfg(verus_keep_ghost)]
use crate::blake2b_update_model as stream;
#[cfg(verus_keep_ghost)]
use crate::initial_hash_model as model;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result@ == model::header(fields@),
))]
pub(crate) fn header(fields: &[u32; 6]) -> [u8; 24] {
    let mut output = [0u8; 24];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            forall|position: int| 0 <= position < 24 ==>
                output@[position] == if position < index as int {
                    model::header(fields@)[position]
                } else { 0u8 },
        decreases 24 - index,
    ))]
    for index in 0..24 {
        output[index] = (fields[index / 4] >> (8 * (index % 4))) as u8;
    }
    output
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires password.len() <= u32::MAX as usize, salt.len() <= u32::MAX as usize,
        secret.len() <= u32::MAX as usize, ad.len() <= u32::MAX as usize,
    ensures result@ == model::h0(fields@, password@, salt@, secret@, ad@),
))]
pub(crate) fn compute_h0(
    fields: &[u32; 6],
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
) -> [u8; 64] {
    let encoded_header = header(fields);
    let password_len = crate::blake2b::h_prime_length(password.len() as u32);
    let salt_len = crate::blake2b::h_prime_length(salt.len() as u32);
    let secret_len = crate::blake2b::h_prime_length(secret.len() as u32);
    let ad_len = crate::blake2b::h_prime_length(ad.len() as u32);
    let parts: [&[u8]; 9] = [
        &encoded_header,
        &password_len,
        password,
        &salt_len,
        salt,
        &secret_len,
        secret,
        &ad_len,
        ad,
    ];
    #[cfg(verus_keep_ghost)]
    proof! {
        model::parts_step(parts@, 0);
        model::parts_step(parts@, 1);
        model::parts_step(parts@, 2);
        model::parts_step(parts@, 3);
        model::parts_step(parts@, 4);
        model::parts_step(parts@, 5);
        model::parts_step(parts@, 6);
        model::parts_step(parts@, 7);
        model::parts_step(parts@, 8);
        model::parts_step(parts@, 9);
        assert(stream::blake2b_parts_prefix(parts@, 9)
            == model::message(fields@, password@, salt@, secret@, ad@));
    }
    crate::blake2b::blake2b(64, &parts)
}

#[cfg(test)]
mod tests {
    #[test]
    fn h0_matches_independent_rfc_field_vectors() {
        let vectors = [
            (32u32, 0u32, "b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109"),
            (32, 1, "c46065815276a0b3e731731c902f1fd80cf776907fbb7b6a5ca72e7b56011feeca446c86dd75b9469a5e6879dec4b72d0863fb939b982e5f397cc7d164fddaa9"),
            (32, 2, "2889de487eb42ae500c0007ed9252f1069eadec40d5765b485de6dc2437a67b8546a2f0acc1a0882db8fcf74714b472e94df421a5da1112ffa11434370a1e997"),
            (35, 2, "36ac009336caf5ca91ced8d553332894fc86cfd498cf88e97c4b6b0951d5c57737ae797c98ba8391eb3810d404d11799c17ad92f6922c710f46c00afad0a0c46"),
        ];
        for (memory, algorithm, expected) in vectors {
            let fields = [4, 32, memory, 3, 0x13, algorithm];
            let digest = super::compute_h0(&fields, &[1u8; 32], &[2u8; 16], &[3u8; 8], &[4u8; 12]);
            let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(actual, expected, "memory={memory}, algorithm={algorithm}");
        }
    }

    #[test]
    fn header_preserves_field_order_and_little_endian() {
        let fields = [0u32, 1, 0x0403_0201, u32::MAX, 0x13, 2];
        let encoded = super::header(&fields);
        for index in 0..6 {
            assert_eq!(&encoded[4 * index..4 * index + 4], &fields[index].to_le_bytes());
        }
    }
}
