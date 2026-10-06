use vstd::prelude::*;
use crate::specs;

verus! {
pub type Blake2bUpdateState = (Seq<u64>, u128, Seq<u8>, nat, nat);

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
    let step = specs::blake2b_update_step(
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
    specs::blake2b_update_step_progress(state.0, state.1, state.2, state.3, suffix);
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