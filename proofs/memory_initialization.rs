use vstd::prelude::*;
use crate::blake2b_long_model as hash;

verus! {
pub open spec fn write_prefix(before: Seq<u64>, start: int, output: Seq<u64>, copied: nat) -> Seq<u64>
    recommends 0 <= start, start + 128 <= before.len(), output.len() == 128, copied <= 128,
{
    Seq::new(before.len(), |position: int|
        if start <= position < start + copied { output[position - start] } else { before[position] })
}

#[verifier::opaque]
pub open spec fn initialized_prefix(
    before: Seq<u64>, h0: Seq<u8>, lane_length: nat, completed: nat,
) -> Seq<u64>
    recommends h0.len() == 64, lane_length >= 2,
        completed <= 2 * u32::MAX as nat,
        ((completed + 1) / 2) * lane_length * 128 <= before.len(),
    decreases completed,
{
    if completed == 0 { before } else {
        let previous = (completed - 1) as nat;
        write_prefix(initialized_prefix(before, h0, lane_length, previous),
            128 * ((previous / 2) * lane_length + previous % 2) as int,
            block(h0, (previous % 2) as u32, (previous / 2) as u32), 128)
    }
}

pub proof fn prefix_step(before: Seq<u64>, h0: Seq<u8>, lane_length: nat, completed: nat)
    requires h0.len() == 64, lane_length >= 2,
        completed + 1 <= 2 * u32::MAX as nat,
        ((completed + 2) / 2) * lane_length * 128 <= before.len(),
    ensures initialized_prefix(before, h0, lane_length, completed + 1)
        == write_prefix(initialized_prefix(before, h0, lane_length, completed),
            128 * ((completed / 2) * lane_length + completed % 2) as int,
            block(h0, (completed % 2) as u32, (completed / 2) as u32), 128),
{
    reveal(initialized_prefix);
}

pub open spec fn seed(h0: Seq<u8>, column: u32, lane: u32) -> Seq<u8>
    recommends h0.len() == 64, column < 2,
{
    h0 + hash::length_prefix(column) + hash::length_prefix(lane)
}

pub open spec fn decode(bytes: Seq<u8>) -> Seq<u64>
    recommends bytes.len() == 1024,
{
    Seq::new(128, |word: int| {
        (bytes[8 * word] as u64)
        | ((bytes[8 * word + 1] as u64) << 8)
        | ((bytes[8 * word + 2] as u64) << 16)
        | ((bytes[8 * word + 3] as u64) << 24)
        | ((bytes[8 * word + 4] as u64) << 32)
        | ((bytes[8 * word + 5] as u64) << 40)
        | ((bytes[8 * word + 6] as u64) << 48)
        | ((bytes[8 * word + 7] as u64) << 56)
    })
}

#[verifier::opaque]
pub open spec fn block(h0: Seq<u8>, column: u32, lane: u32) -> Seq<u64>
    recommends h0.len() == 64, column < 2,
{
    decode(hash::h_prime(1024, seed(h0, column, lane)))
}
}