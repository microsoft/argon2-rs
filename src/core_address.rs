//! Data-independent Argon2 address-block generation.

#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
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

#[verifier::opaque]
pub open spec fn zero_words() -> Seq<u64> {
    Seq::new(128, |_index: int| 0u64)
}

#[verifier::opaque]
pub open spec fn address_g(previous: Seq<u64>, reference: Seq<u64>, old_next: Seq<u64>) -> Seq<u64> {
    specs::fill_block_result(previous, reference, old_next, false)
}

#[verifier::opaque]
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
        assert(zero@ == zero_words()) by {
            reveal(zero_words);
            assert forall|index: int| 0 <= index < 128 implies
                zero@[index] == zero_words()[index] by {}
            assert(zero@ =~= zero_words());
        }
        generated_address_composition(
            zero@, input_block@, temp@, old(address_block)@, address_block@,
        );
    }
    0
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
}
