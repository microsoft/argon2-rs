use crate::specs::initialization::{initialized_prefix, block};
use vstd::prelude::*;

verus! {
pub open spec fn write_prefix(before: Seq<u64>, start: int, output: Seq<u64>, copied: nat) -> Seq<u64>
    recommends 0 <= start, start + 128 <= before.len(), output.len() == 128, copied <= 128,
{
    Seq::new(before.len(), |position: int|
        if start <= position < start + copied { output[position - start] } else { before[position] })
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


}