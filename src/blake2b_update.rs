//! Iterative streaming update loop for the BLAKE2b state.

use crate::blake2b_buffer::update_step;

#[cfg(verus_keep_ghost)]
use crate::blake2b_update_model as model;
#[cfg(verus_keep_ghost)]
use crate::specs;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_spec(
    requires *old(buffered_len) <= 128,
        *old(counter) as int + *old(buffered_len) as int + old(data)@.len() as int
            <= u128::MAX as int,
    ensures final(data)@.len() == 0, *final(buffered_len) <= 128,
        *final(counter) as int + *final(buffered_len) as int
            == *old(counter) as int + *old(buffered_len) as int + old(data)@.len() as int,
        exists|trace: Seq<model::Blake2bUpdateState>|
            model::blake2b_update_trace(
                (old(h)@, *old(counter), old(buffer)@, *old(buffered_len) as nat, 0nat),
                old(data)@, trace,
            ) && trace.last() == (
                final(h)@, *final(counter), final(buffer)@,
                *final(buffered_len) as nat, old(data)@.len(),
            ),
        exists|blocks: nat| model::blake2b_update_semantic_at(
            (old(h)@, *old(counter), old(buffer)@, *old(buffered_len) as nat, 0nat),
            old(data)@,
            (final(h)@, *final(counter), final(buffer)@,
                *final(buffered_len) as nat, old(data)@.len()),
            blocks,
        ),
        specs::blake2b_finalize_result(
            final(h)@, *final(counter), final(buffer)@, *final(buffered_len) as nat,
        ) == model::blake2b_stream_digest(
            old(h)@, *old(counter), old(buffer)@.take(*old(buffered_len) as int) + old(data)@,
        ),
))]
pub(crate) fn update(
    h: &mut [u64; 8],
    counter: &mut u128,
    buffer: &mut [u8; 128],
    buffered_len: &mut usize,
    data: &mut &[u8],
) {
    let input = *data;
    let mut offset = 0usize;
    #[cfg(verus_keep_ghost)]
    proof_decl! {
        let ghost initial = (h@, *counter, buffer@, *buffered_len as nat, 0nat);
        let ghost mut trace = Seq::empty().push(initial);
        let ghost mut blocks = 0nat;
    }
    #[cfg(verus_keep_ghost)]
    proof! {
        model::blake2b_update_semantic_initial(initial, input@);
    }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            input@ == old(data)@,
            offset <= input.len(), *buffered_len <= 128,
            *counter as int + *buffered_len as int + input.len() as int - offset as int
                == *old(counter) as int + *old(buffered_len) as int + input.len() as int,
            *old(counter) as int + *old(buffered_len) as int + input.len() as int
                <= u128::MAX as int,
            initial == (old(h)@, *old(counter), old(buffer)@, *old(buffered_len) as nat, 0nat),
            model::blake2b_update_trace(initial, input@, trace),
            trace.last() == (h@, *counter, buffer@, *buffered_len as nat, offset as nat),
            model::blake2b_update_semantic_at(initial, input@, trace.last(), blocks),
        decreases input.len() - offset,
    ))]
    while offset < input.len() {
        #[cfg(verus_keep_ghost)]
        proof! {
            model::blake2b_update_semantic_next(initial, input@, trace.last(), blocks);
            if trace.last().3 == 128 {
                blocks = blocks + 1;
            }
            model::blake2b_update_trace_extend(initial, input@, trace);
            reveal(model::blake2b_update_next);
            trace = trace.push(model::blake2b_update_next(trace.last(), input@));
        }
        let (next_h, next_counter, next_buffer, next_len, consumed) =
            update_step(*h, *counter, *buffer, *buffered_len, &input[offset..]);
        *h = next_h;
        *counter = next_counter;
        *buffer = next_buffer;
        *buffered_len = next_len;
        offset += consumed;
    }
    *data = &input[offset..];
    #[cfg(verus_keep_ghost)]
    proof! {
        model::blake2b_update_semantic_finalize(initial, input@, trace.last(), blocks);
        assert(exists|witness: Seq<model::Blake2bUpdateState>|
            model::blake2b_update_trace(initial, input@, witness)
            && witness.last() == (h@, *counter, buffer@, *buffered_len as nat, input@.len())) by {
            assert(model::blake2b_update_trace(initial, input@, trace));
        }
        assert(exists|completed: nat| model::blake2b_update_semantic_at(
            initial, input@,
            (h@, *counter, buffer@, *buffered_len as nat, input@.len()), completed,
        )) by {
            assert(model::blake2b_update_semantic_at(initial, input@, trace.last(), blocks));
        }
    }
}
