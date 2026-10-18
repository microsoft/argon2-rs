use crate::specs::digest::{blake2b_nonfinal_blocks, blake2b_stream_digest};
use vstd::prelude::*;
use crate::specs;

verus! {
pub type Blake2bUpdateState = (Seq<u64>, u128, Seq<u8>, nat, nat);

#[verifier::opaque]
pub open spec fn blake2b_parts_prefix(parts: Seq<&[u8]>, completed: nat) -> Seq<u8>
    recommends completed <= parts.len(),
    decreases completed,
{
    if completed == 0 {
        Seq::empty()
    } else {
        blake2b_parts_prefix(parts, (completed - 1) as nat) + parts[(completed - 1) as int]@
    }
}

pub proof fn blake2b_parts_prefix_bound(parts: Seq<&[u8]>, completed: nat, total: nat)
    requires completed <= total <= parts.len(),
    ensures blake2b_parts_prefix(parts, completed).len() <= blake2b_parts_prefix(parts, total).len(),
    decreases total,
{
    reveal(blake2b_parts_prefix);
    if completed < total {
        blake2b_parts_prefix_bound(parts, completed, (total - 1) as nat);
    }
}

pub proof fn blake2b_buffer_append_composition(
    buffer: Seq<u8>, start: int, first: Seq<u8>, second: Seq<u8>,
)
    requires buffer.len() == 128, 0 <= start,
        start + first.len() + second.len() <= 128,
    ensures crate::invariant_specs::blake2b_buffer_append(
        crate::invariant_specs::blake2b_buffer_append(buffer, start, first),
        start + first.len(), second,
    ) == crate::invariant_specs::blake2b_buffer_append(buffer, start, first + second),
{
    let left = crate::invariant_specs::blake2b_buffer_append(
        crate::invariant_specs::blake2b_buffer_append(buffer, start, first), start + first.len(), second,
    );
    let right = crate::invariant_specs::blake2b_buffer_append(buffer, start, first + second);
    assert(left =~= right);
}

pub proof fn blake2b_nonfinal_blocks_len(
    initial_h: Seq<u64>, initial_counter: u128, message: Seq<u8>, blocks: nat,
)
    requires initial_h.len() == 8, 128 * blocks <= message.len(),
        initial_counter as int + 128 * blocks <= u128::MAX as int,
    ensures blake2b_nonfinal_blocks(initial_h, initial_counter, message, blocks).len() == 8,
    decreases blocks,
{
    reveal(blake2b_nonfinal_blocks);
    if blocks > 0 {
        blake2b_nonfinal_blocks_len(initial_h, initial_counter, message, (blocks - 1) as nat);
    }
}

pub proof fn blake2b_nonfinal_blocks_prefix(
    initial_h: Seq<u64>, initial_counter: u128, left: Seq<u8>, right: Seq<u8>, blocks: nat,
)
    requires initial_h.len() == 8, 128 * blocks <= left.len(), 128 * blocks <= right.len(),
        initial_counter as int + 128 * blocks <= u128::MAX as int,
        left.take((128 * blocks) as int) == right.take((128 * blocks) as int),
    ensures blake2b_nonfinal_blocks(initial_h, initial_counter, left, blocks)
        == blake2b_nonfinal_blocks(initial_h, initial_counter, right, blocks),
    decreases blocks,
{
    hide(specs::blake2b_compress_block);
    reveal(blake2b_nonfinal_blocks);
    if blocks > 0 {
        let before = 128 * (blocks - 1);
        let after = (128 * blocks) as int;
        assert forall|index: int| 0 <= index < after implies
            #[trigger] left[index] == right[index] by {
            assert(left.take(after)[index] == left[index]);
            assert(right.take(after)[index] == right[index]);
        }
        assert(left.take(before) =~= right.take(before));
        assert(left.subrange(before, after) =~= right.subrange(before, after));
        blake2b_nonfinal_blocks_prefix(initial_h, initial_counter, left, right, (blocks - 1) as nat);
    }
}

pub proof fn blake2b_nonfinal_blocks_split(
    initial_h: Seq<u64>, initial_counter: u128, message: Seq<u8>, first: nat, additional: nat,
)
    requires initial_h.len() == 8, 128 * (first + additional) <= message.len(),
        initial_counter as int + 128 * (first + additional) <= u128::MAX as int,
    ensures blake2b_nonfinal_blocks(initial_h, initial_counter, message, first + additional)
        == blake2b_nonfinal_blocks(
            blake2b_nonfinal_blocks(initial_h, initial_counter, message, first),
            (initial_counter as int + 128 * first) as u128,
            message.skip((128 * first) as int), additional,
        ),
    decreases additional,
{
    hide(specs::blake2b_compress_block);
    blake2b_nonfinal_blocks_len(initial_h, initial_counter, message, first);
    reveal(blake2b_nonfinal_blocks);
    if additional > 0 {
        blake2b_nonfinal_blocks_split(initial_h, initial_counter, message, first, (additional - 1) as nat);
        let suffix = message.skip((128 * first) as int);
        assert(message.subrange(128 * (first + additional - 1), (128 * (first + additional)) as int)
            =~= suffix.subrange(128 * (additional - 1), (128 * additional) as int));
    }
}

#[verifier::opaque]
pub open spec fn blake2b_update_semantic_at(
    initial: Blake2bUpdateState, input: Seq<u8>, state: Blake2bUpdateState, blocks: nat,
) -> bool {
    let message = initial.2.take(initial.3 as int) + input;
    &&& blake2b_update_state_valid(initial, input.len())
    &&& initial.4 == 0
    &&& blake2b_update_state_valid(state, input.len())
    &&& state.1 as int == initial.1 as int + 128 * blocks
    &&& 128 * blocks + state.3 == initial.3 + state.4
    &&& (initial.3 + state.4 > 0 ==> state.3 > 0)
    &&& state.0 == blake2b_nonfinal_blocks(initial.0, initial.1, message, blocks)
    &&& forall|index: int| 0 <= index < state.3 ==>
        #[trigger] state.2[index] == message[128 * blocks + index]
}

pub proof fn blake2b_update_semantic_initial(initial: Blake2bUpdateState, input: Seq<u8>)
    requires blake2b_update_state_valid(initial, input.len()), initial.4 == 0,
    ensures blake2b_update_semantic_at(initial, input, initial, 0),
{
    reveal(blake2b_update_semantic_at);
    reveal(blake2b_nonfinal_blocks);
    let message = initial.2.take(initial.3 as int) + input;
    assert forall|index: int| 0 <= index < initial.3 implies
        #[trigger] initial.2[index] == message[index] by {
        assert(initial.2.take(initial.3 as int)[index] == initial.2[index]);
    }
}

pub proof fn blake2b_update_semantic_next(
    initial: Blake2bUpdateState, input: Seq<u8>, state: Blake2bUpdateState, blocks: nat,
)
    requires blake2b_update_semantic_at(initial, input, state, blocks), state.4 < input.len(),
    ensures blake2b_update_semantic_at(
        initial, input, blake2b_update_next(state, input),
        if state.3 == 128 { blocks + 1 } else { blocks },
    ),
{
    hide(specs::blake2b_compress_block);
    reveal(blake2b_update_semantic_at);
    blake2b_update_next_valid(state, input);
    reveal(blake2b_update_next);
    let message = initial.2.take(initial.3 as int) + input;
    let suffix = input.subrange(state.4 as int, input.len() as int);
    crate::invariant_specs::blake2b_update_step_progress(state.0, state.1, state.2, state.3, suffix);
    let next = blake2b_update_next(state, input);
    let next_blocks = if state.3 == 128 { blocks + 1 } else { blocks };
    if state.3 == 128 {
        let full_block = message.subrange((128 * blocks) as int, (128 * (blocks + 1)) as int);
        assert(state.2 =~= full_block);
        reveal(blake2b_nonfinal_blocks);
        assert(next.0 == blake2b_nonfinal_blocks(initial.0, initial.1, message, next_blocks));
    }
    assert forall|index: int| 0 <= index < next.3 implies
        #[trigger] next.2[index] == message[128 * next_blocks + index] by {
        if state.3 < 128 && index < state.3 {
            assert(state.2[index] == message[128 * blocks + index]);
        } else {
            let start = if state.3 == 128 { 0int } else { state.3 as int };
            assert(128 * next_blocks + index == initial.3 + state.4 + index - start);
            assert(message[initial.3 + state.4 + index - start] == input[state.4 + index - start]);
        }
    }
}

pub proof fn blake2b_update_semantic_finalize(
    initial: Blake2bUpdateState, input: Seq<u8>, state: Blake2bUpdateState, blocks: nat,
)
    requires blake2b_update_semantic_at(initial, input, state, blocks), state.4 == input.len(),
    ensures specs::blake2b_finalize_result(state.0, state.1, state.2, state.3)
        == blake2b_stream_digest(initial.0, initial.1, initial.2.take(initial.3 as int) + input),
{
    hide(specs::blake2b_compress_block);
    reveal(blake2b_update_semantic_at);
    reveal(blake2b_stream_digest);
    let message = initial.2.take(initial.3 as int) + input;
    let canonical_blocks = if message.len() == 0 { 0nat } else { ((message.len() - 1) / 128) as nat };
    if message.len() > 0 {
        assert(1 <= state.3 <= 128);
        assert((message.len() - 1) / 128 == blocks);
    }
    assert(canonical_blocks == blocks);
    let padded = Seq::new(128, |index: int|
        if index < state.3 { message[128 * blocks + index] } else { 0u8 });
    assert(specs::blake2b_pad_final_block(state.2, state.3) =~= padded);
}

pub open spec fn blake2b_update_restart(state: Blake2bUpdateState) -> Blake2bUpdateState {
    (state.0, state.1, state.2, state.3, 0nat)
}

pub proof fn blake2b_update_semantic_compose(
    initial: Blake2bUpdateState, first: Seq<u8>, second: Seq<u8>,
    middle: Blake2bUpdateState, final_state: Blake2bUpdateState, first_blocks: nat, second_blocks: nat,
)
    requires blake2b_update_state_valid(initial, (first + second).len()), initial.4 == 0,
        blake2b_update_semantic_at(initial, first, middle, first_blocks), middle.4 == first.len(),
        blake2b_update_semantic_at(blake2b_update_restart(middle), second, final_state, second_blocks),
        final_state.4 == second.len(),
    ensures blake2b_update_semantic_at(
        initial, first + second,
        (final_state.0, final_state.1, final_state.2, final_state.3, first.len() + second.len()),
        first_blocks + second_blocks,
    ),
{
    hide(specs::blake2b_compress_block);
    reveal(blake2b_update_semantic_at);
    let first_message = initial.2.take(initial.3 as int) + first;
    let message = first_message + second;
    let suffix_message = middle.2.take(middle.3 as int) + second;
    assert(message =~= initial.2.take(initial.3 as int) + (first + second));
    assert(first_message.take((128 * first_blocks) as int)
        =~= message.take((128 * first_blocks) as int));
    blake2b_nonfinal_blocks_prefix(initial.0, initial.1, first_message, message, first_blocks);
    assert forall|index: int| 0 <= index < suffix_message.len() implies
        #[trigger] suffix_message[index] == message[128 * first_blocks + index] by {
        if index < middle.3 {
            assert(middle.2[index] == first_message[128 * first_blocks + index]);
        } else {
            assert(128 * first_blocks + index == first_message.len() + index - middle.3);
        }
    }
    assert(message.skip((128 * first_blocks) as int) =~= suffix_message);
    blake2b_nonfinal_blocks_split(initial.0, initial.1, message, first_blocks, second_blocks);
    assert forall|index: int| 0 <= index < final_state.3 implies
        #[trigger] final_state.2[index] == message[128 * (first_blocks + second_blocks) + index] by {
        assert(final_state.2[index] == suffix_message[128 * second_blocks + index]);
    }
}

pub proof fn blake2b_update_partition_independence(
    initial: Blake2bUpdateState, first: Seq<u8>, second: Seq<u8>,
    middle: Blake2bUpdateState, split_final: Blake2bUpdateState, joined_final: Blake2bUpdateState,
    first_blocks: nat, second_blocks: nat, joined_blocks: nat,
)
    requires blake2b_update_state_valid(initial, (first + second).len()), initial.4 == 0,
        blake2b_update_semantic_at(initial, first, middle, first_blocks), middle.4 == first.len(),
        blake2b_update_semantic_at(blake2b_update_restart(middle), second, split_final, second_blocks),
        split_final.4 == second.len(),
        blake2b_update_semantic_at(initial, first + second, joined_final, joined_blocks),
        joined_final.4 == first.len() + second.len(),
    ensures specs::blake2b_finalize_result(split_final.0, split_final.1, split_final.2, split_final.3)
        == specs::blake2b_finalize_result(joined_final.0, joined_final.1, joined_final.2, joined_final.3),
{
    blake2b_update_semantic_compose(initial, first, second, middle, split_final, first_blocks, second_blocks);
    let combined_final = (split_final.0, split_final.1, split_final.2, split_final.3, first.len() + second.len());
    blake2b_update_semantic_finalize(initial, first + second, combined_final, first_blocks + second_blocks);
    blake2b_update_semantic_finalize(initial, first + second, joined_final, joined_blocks);
}

pub open spec fn blake2b_update_state_valid(state: Blake2bUpdateState, input_len: nat) -> bool {
    &&& state.0.len() == 8
    &&& state.2.len() == 128
    &&& state.3 <= 128
    &&& state.4 <= input_len
    &&& state.1 as int + state.3 as int + input_len as int - state.4 as int
        <= u128::MAX as int
}

#[verifier::opaque]
pub open spec fn blake2b_update_next(state: Blake2bUpdateState, input: Seq<u8>) -> Blake2bUpdateState
    recommends blake2b_update_state_valid(state, input.len()), state.4 < input.len(),
{
    let step = crate::invariant_specs::blake2b_update_step(
        state.0, state.1, state.2, state.3, input.subrange(state.4 as int, input.len() as int),
    );
    (step.0, step.1, step.2, step.3, state.4 + step.4)
}

pub proof fn blake2b_update_next_valid(state: Blake2bUpdateState, input: Seq<u8>)
    requires blake2b_update_state_valid(state, input.len()), state.4 < input.len(),
    ensures blake2b_update_state_valid(blake2b_update_next(state, input), input.len()),
{
    reveal(blake2b_update_next);
    let suffix = input.subrange(state.4 as int, input.len() as int);
    crate::invariant_specs::blake2b_update_step_progress(state.0, state.1, state.2, state.3, suffix);
}

#[verifier::opaque]
pub open spec fn blake2b_update_edge_at(
    trace: Seq<Blake2bUpdateState>, input: Seq<u8>, index: int,
) -> bool {
    trace[index].4 < input.len()
        && trace[index + 1] == blake2b_update_next(trace[index], input)
}

pub proof fn blake2b_update_edge_push_prefix(
    trace: Seq<Blake2bUpdateState>, next: Blake2bUpdateState, input: Seq<u8>, index: int,
)
    requires 0 <= index < trace.len() - 1,
    ensures blake2b_update_edge_at(trace.push(next), input, index)
        == blake2b_update_edge_at(trace, input, index),
{
    reveal(blake2b_update_edge_at);
    vstd::seq::lemma_seq_push_index_different(trace, next, index);
    vstd::seq::lemma_seq_push_index_different(trace, next, index + 1);
}

pub proof fn blake2b_update_edge_push_last(
    trace: Seq<Blake2bUpdateState>, next: Blake2bUpdateState, input: Seq<u8>,
)
    requires trace.len() > 0, trace.last().4 < input.len(),
        next == blake2b_update_next(trace.last(), input),
    ensures blake2b_update_edge_at(trace.push(next), input, trace.len() - 1),
{
    reveal(blake2b_update_edge_at);
    vstd::seq::lemma_seq_push_index_different(trace, next, trace.len() - 1);
    vstd::seq::lemma_seq_push_index_same(trace, next, trace.len() as int);
}

pub open spec fn blake2b_update_trace(
    initial: Blake2bUpdateState, input: Seq<u8>, trace: Seq<Blake2bUpdateState>,
) -> bool {
    &&& trace.len() > 0
    &&& trace[0] == initial
    &&& forall|index: int| 0 <= index < trace.len() ==>
        blake2b_update_state_valid(#[trigger] trace[index], input.len())
    &&& forall|index: int| 0 <= index < trace.len() - 1 ==>
        #[trigger] blake2b_update_edge_at(trace, input, index)
}

pub proof fn blake2b_update_trace_extend(
    initial: Blake2bUpdateState, input: Seq<u8>, trace: Seq<Blake2bUpdateState>,
)
    requires blake2b_update_trace(initial, input, trace), trace.last().4 < input.len(),
    ensures blake2b_update_trace(initial, input, trace.push(blake2b_update_next(trace.last(), input))),
{
    let state = trace.last();
    blake2b_update_next_valid(state, input);
    let next = blake2b_update_next(state, input);
    let extended = trace.push(next);
    assert(extended.len() == trace.len() + 1);
    assert(extended[0] == trace[0]);
    assert forall|index: int| 0 <= index < extended.len() implies
        blake2b_update_state_valid(#[trigger] extended[index], input.len()) by {
        if index < trace.len() {
            vstd::seq::lemma_seq_push_index_different(trace, next, index);
            assert(blake2b_update_state_valid(trace[index], input.len()));
        } else {
            vstd::seq::lemma_seq_push_index_same(trace, next, index);
        }
    }
    blake2b_update_edge_push_last(trace, next, input);
    assert forall|index: int| 0 <= index < extended.len() - 1 implies
        #[trigger] blake2b_update_edge_at(extended, input, index) by {
        if index < trace.len() - 1 {
            blake2b_update_edge_push_prefix(trace, next, input, index);
            assert(blake2b_update_edge_at(trace, input, index));
        } else {
            assert(index == trace.len() - 1);
        }
    }
}
}