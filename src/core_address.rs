//! Data-independent Argon2 address-block generation.

#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
// RFC 9106 section 3.4.1.2: pass/lane/slice/memory/passes/type/counter encoding.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.4.1.2
pub open spec fn address_input(
    pass: u32, lane: u32, slice: u32, blocks: u32, passes: u32, algorithm: u32,
) -> Seq<u64> {
    Seq::new(128, |index: int| if index == 0 { pass as u64 }
        else if index == 1 { lane as u64 }
        else if index == 2 { slice as u64 }
        else if index == 3 { blocks as u64 }
        else if index == 4 { passes as u64 }
        else if index == 5 { algorithm as u64 }
        else { 0u64 })
}

// RFC 9106 section 3.4.1.2: the zero block used for address generation.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.4.1.2
// Keep this opaque to avoid expanding zero-block sequences throughout traversal.
#[verifier::opaque]
pub open spec fn zero_words() -> Seq<u64> {
    Seq::new(128, |_index: int| 0u64)
}

#[verifier::opaque]
// RFC 9106 section 3.5: G without the later-pass destination XOR.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.5
pub open spec fn address_g(previous: Seq<u64>, reference: Seq<u64>, old_next: Seq<u64>) -> Seq<u64> {
    specs::fill_block_result(previous, reference, old_next, false)
}

#[verifier::opaque]
// RFC 9106 section 3.4.1.2: G(zero, G(zero, encoded input)).
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.4.1.2
pub open spec fn generated_address_block(input: Seq<u64>, old_address: Seq<u64>) -> Seq<u64> {
    address_g(zero_words(), address_g(zero_words(), input, zero_words()), old_address)
}

pub proof fn generated_address_composition(
    zero: Seq<u64>,
    input: Seq<u64>,
    temp: Seq<u64>,
    old_address: Seq<u64>,
    new_address: Seq<u64>,
)
    requires zero == zero_words(), input.len() == 128, temp.len() == 128,
        old_address.len() == 128, new_address.len() == 128,
        temp == address_g(zero, input, zero),
        new_address == address_g(zero, temp, old_address),
    ensures new_address == generated_address_block(input, old_address),
{
    reveal(generated_address_block);
}

pub proof fn generated_address_independent(
    input: Seq<u64>, first: Seq<u64>, second: Seq<u64>,
)
    ensures generated_address_block(input, first) == generated_address_block(input, second),
{
    reveal(generated_address_block);
    reveal(address_g);
}

pub proof fn schedule_successor(index: u32)
    requires index < u32::MAX,
    ensures index as int / 128 + 1 == (index as int + 1) / 128
        + if (index as int + 1) % 128 == 0 { 0int } else { 1int },
{
}
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result@ == address_input(pass, lane, slice, blocks, passes, algorithm),
))]
pub(crate) fn initial_input(
    pass: u32,
    lane: u32,
    slice: u32,
    blocks: u32,
    passes: u32,
    algorithm: u32,
) -> [u64; 128] {
    let mut words = [0u64; 128];
    words[0] = pass as u64;
    words[1] = lane as u64;
    words[2] = slice as u64;
    words[3] = blocks as u64;
    words[4] = passes as u64;
    words[5] = algorithm as u64;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(words@ =~= address_input(pass, lane, slice, blocks, passes, algorithm));
    }
    words
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    ensures final(next)@ == address_g(prev@, reference@, old(next)@),
))]
fn compress_into(prev: &[u64; 128], reference: &[u64; 128], next: &mut [u64; 128]) {
    crate::block_g_fill::fill_block(prev, reference, next, false);
    #[cfg(verus_keep_ghost)]
    proof! { reveal(address_g); }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires old(input_block)@[6] < u64::MAX,
    ensures final(input_block)@ == old(input_block)@.update(
        6, (old(input_block)@[6] as int + 1) as u64,
    ),
))]
fn increment_counter(input_block: &mut [u64; 128]) {
    input_block[6] += 1;
}

#[cfg_attr(verus_keep_ghost, verifier::spinoff_prover)]
#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires old(input_block)@[6] < u64::MAX,
    ensures result == 0,
        final(input_block)@ == old(input_block)@.update(
            6, (old(input_block)@[6] as int + 1) as u64,
        ),
        final(address_block)@ == generated_address_block(final(input_block)@, old(address_block)@),
))]
pub(crate) fn next_addresses(input_block: &mut [u64; 128], address_block: &mut [u64; 128]) -> u64 {
    increment_counter(input_block);
    let zero = [0u64; 128];
    let mut temp = [0u64; 128];
    compress_into(&zero, input_block, &mut temp);
    compress_into(&zero, &temp, address_block);
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(zero@ =~= zero_words()) by {
            reveal(zero_words);
        }
        generated_address_composition(
            zero@, input_block@, temp@, old(address_block)@, address_block@,
        );
    }
    0
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires start == 0 || start == 2,
    ensures result.0@ == address_input(pass, lane, slice, blocks, passes, algorithm)
            .update(6, if start == 2 { 1u64 } else { 0u64 }),
        result.0@[6] == start as int / 128
            + if start % 128 == 0 { 0int } else { 1int },
        result.1@ == if start == 2 {
            generated_address_block(result.0@, zero_words())
        } else { zero_words() },
))]
pub(crate) fn initial_state(
    pass: u32,
    lane: u32,
    slice: u32,
    blocks: u32,
    passes: u32,
    algorithm: u32,
    start: u32,
) -> ([u64; 128], [u64; 128]) {
    let mut input = initial_input(pass, lane, slice, blocks, passes, algorithm);
    let mut address = [0u64; 128];
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(zero_words);
        assert(address@ =~= zero_words());
    }
    if start == 2 {
        next_addresses(&mut input, &mut address);
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        if start == 0 {
            assert(input@ == address_input(pass, lane, slice, blocks, passes, algorithm)
                .update(6, 0u64));
        }
    }
    (input, address)
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires old(input_block)@[6] == index as int / 128
        + if index % 128 == 0 { 0int } else { 1int },
        index % 128 != 0 ==> old(address_block)@
            == generated_address_block(old(input_block)@, zero_words()),
    ensures final(input_block)@[6] == index as int / 128 + 1,
        final(input_block)@ == old(input_block)@.update(
            6, final(input_block)@[6]),
        final(address_block)@ == if index % 128 == 0 {
            generated_address_block(final(input_block)@, old(address_block)@)
        } else { old(address_block)@ },
        final(address_block)@ == generated_address_block(final(input_block)@, zero_words()),
        result == final(address_block)@[index as int % 128],
))]
pub(crate) fn scheduled_word(
    input_block: &mut [u64; 128],
    address_block: &mut [u64; 128],
    index: u32,
) -> u64 {
    if index % 128 == 0 {
        next_addresses(input_block, address_block);
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(input_block@ == old(input_block)@.update(6, input_block@[6]));
        if index % 128 == 0 {
            generated_address_independent(input_block@, old(address_block)@, zero_words());
        }
    }
    address_block[(index % 128) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_fields_and_zero_tail() {
        let input = initial_input(7, 3, 2, 1024, 9, 1);
        assert_eq!(&input[..6], &[7, 3, 2, 1024, 9, 1]);
        assert!(input[6..].iter().all(|word| *word == 0));
        let input = initial_input(u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX, u32::MAX);
        assert!(input[..6].iter().all(|word| *word == u32::MAX as u64));
        assert!(input[6..].iter().all(|word| *word == 0));
    }

    #[test]
    fn schedule_matches_direct_two_g_across_boundaries() {
        for start in [0u32, 2u32] {
            let (mut input, mut address) = initial_state(0, 1, 0, 1024, 3, 1, start);
            let mut expected_input = initial_input(0, 1, 0, 1024, 3, 1);
            let mut expected_address = [0u64; 128];
            let zero = [0u64; 128];
            let mut temp = [0u64; 128];
            if start == 2 {
                expected_input[6] += 1;
                crate::block::compress(&zero, &expected_input, &mut temp);
                crate::block::compress(&zero, &temp, &mut expected_address);
            }
            for index in start..260 {
                if index % 128 == 0 {
                    expected_input[6] += 1;
                    crate::block::compress(&zero, &expected_input, &mut temp);
                    crate::block::compress(&zero, &temp, &mut expected_address);
                }
                assert_eq!(
                    scheduled_word(&mut input, &mut address, index),
                    expected_address[(index % 128) as usize]
                );
                assert_eq!(input, expected_input);
                assert_eq!(address, expected_address);
                assert_eq!(input[6], index as u64 / 128 + 1);
            }
        }
    }
}
