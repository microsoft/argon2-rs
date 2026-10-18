//! Shared Argon2 segment traversal.

#[cfg(verus_keep_ghost)]
use crate::core_address;
use crate::memory::Memory;
#[cfg(verus_keep_ghost)]
use crate::{memory, specs};
use crate::{Algorithm, Version};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[derive(Clone, Copy)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) struct Segment {
    pub algorithm: Algorithm,
    pub version: Version,
    pub lanes: u32,
    pub lane_length: u32,
    pub segment_length: u32,
    pub memory_blocks: u32,
    pub total_passes: u32,
    pub pass: u32,
    pub lane: u32,
    pub slice: u32,
}

#[cfg(verus_keep_ghost)]
verus! {
impl Segment {
    pub(crate) open spec fn valid(&self) -> bool {
        self.lanes > 0 && self.lane < self.lanes && self.slice < 4
        && self.segment_length >= 2
        && self.lane_length as int == 4 * self.segment_length as int
        && self.memory_blocks as int == self.lanes as int * self.lane_length as int
        && self.pass < self.total_passes
    }
}

// RFC 9106 section 3.2, steps 3-5: skip the two pre-initialized blocks.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub(crate) open spec fn segment_start(seg: Segment) -> int {
    if seg.pass == 0 && seg.slice == 0 { 2int } else { 0int }
}

// RFC 9106 section 3.4.1.3: Argon2id switches after the first two slices.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.4.1.3
pub(crate) open spec fn independent(seg: Segment) -> bool {
    seg.algorithm as u32 == 1
        || (seg.algorithm as u32 == 2 && seg.pass == 0 && seg.slice < 2)
}

#[verifier::opaque]
// RFC 9106 section 3.4.1: obtain J1/J2 from addresses or the previous block.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.4.1
pub(crate) open spec fn segment_random(words: Seq<u64>, seg: Segment, index: u32) -> u64 {
    if independent(seg) {
        let input = core_address::address_input(seg.pass, seg.lane, seg.slice,
            seg.memory_blocks, seg.total_passes, seg.algorithm as u32)
            .update(6, (index as int / 128 + 1) as u64);
        core_address::generated_address_block(input, core_address::zero_words())[index as int % 128]
    } else {
        words[128 * specs::predecessor_position(seg.lane, seg.lane_length,
            seg.slice, seg.segment_length, index)]
    }
}

#[verifier::opaque]
// RFC 9106 section 3.2, steps 5-6: one selected-block update.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub(crate) open spec fn segment_step(words: Seq<u64>, seg: Segment, index: u32) -> Seq<u64> {
    let previous = specs::predecessor_position(seg.lane, seg.lane_length,
        seg.slice, seg.segment_length, index);
    let current = seg.lane as int * seg.lane_length as int
        + seg.slice as int * seg.segment_length as int + index as int;
    let reference = specs::reference_position(seg.pass, seg.slice, seg.segment_length,
        seg.lane_length, seg.lanes, seg.lane, index, segment_random(words, seg, index));
    memory::fill_result(words, previous, reference, current,
        seg.version as u32 == 0x13 && seg.pass > 0)
}

#[verifier::opaque]
// RFC 9106 section 3.2, steps 5-6: ordered updates within one segment.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub(crate) open spec fn segment_prefix(before: Seq<u64>, seg: Segment, completed: nat) -> Seq<u64>
    decreases completed,
{
    if completed == 0 { before }
    else { segment_step(segment_prefix(before, seg, (completed - 1) as nat),
        seg, (segment_start(seg) + completed as int - 1) as u32) }
}

pub(crate) proof fn segment_advance(before: Seq<u64>, seg: Segment, index: u32)
    requires segment_start(seg) <= index as int,
    ensures segment_prefix(before, seg, (index as int + 1 - segment_start(seg)) as nat)
        == segment_step(segment_prefix(before, seg, (index as int - segment_start(seg)) as nat), seg, index),
{
    reveal(segment_prefix);
}
}

#[inline(always)]
#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires seg.valid(), old(memory).words().len() == seg.memory_blocks as int * 128,
        forall|arena: &mut Memory, prev: usize, reference: usize, curr: usize, xor: bool, first: bool|
            (prev as int + 1) * 128 <= arena.words().len()
            && (reference as int + 1) * 128 <= arena.words().len()
            && (curr as int + 1) * 128 <= arena.words().len()
            && prev != curr && reference != curr
            ==> call_requires(fill, (arena, prev, reference, curr, xor, first)),
        forall|arena: &mut Memory, prev: usize, reference: usize, curr: usize, xor: bool, first: bool|
            call_ensures(fill, (arena, prev, reference, curr, xor, first), ())
            ==> (final(arena).words().len() == arena.words().len()
                && final(arena).words() == memory::fill_result(
                    arena.words(), prev as int, reference as int, curr as int, xor)),
    ensures final(memory).words().len() == old(memory).words().len(),
        final(memory).words() == segment_prefix(old(memory).words(), *seg,
            (seg.segment_length as int - segment_start(*seg)) as nat),
))]
pub(crate) fn walk_segment<F>(memory: &mut Memory, seg: &Segment, mut fill: F)
where
    F: FnMut(&mut Memory, usize, usize, usize, bool, bool),
{
    let Segment {
        algorithm,
        version,
        lanes,
        lane_length,
        segment_length,
        memory_blocks,
        total_passes,
        pass,
        lane,
        slice,
    } = *seg;
    let _word_count = memory.word_count();
    let with_xor = crate::core_primitives::xor_on_pass(version as u32, pass);
    let data_independent =
        crate::core_primitives::uses_independent_addresses(algorithm as u32, pass, slice);
    let starting_index: u32 = if pass == 0 && slice == 0 { 2 } else { 0 };
    let (mut input, mut address) = if data_independent {
        crate::core_address::initial_state(
            pass,
            lane,
            slice,
            memory_blocks,
            total_passes,
            algorithm as u32,
            starting_index,
        )
    } else {
        ([0u64; 128], [0u64; 128])
    };
    #[cfg(verus_keep_ghost)]
    proof_decl! { let ghost initial = memory.words(); }
    #[cfg(verus_keep_ghost)]
    proof! { reveal(segment_prefix); }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            memory.words().len() == memory_blocks as int * 128,
            memory.words() == segment_prefix(initial, *seg, (index as int - starting_index as int) as nat),
            data_independent ==> input@ == core_address::address_input(
                pass, lane, slice, memory_blocks, total_passes, algorithm as u32).update(6, input@[6]),
            data_independent ==> input@[6] == index as int / 128
                + if index % 128 == 0 { 0int } else { 1int },
            data_independent && index % 128 != 0 ==> address@
                == core_address::generated_address_block(input@, core_address::zero_words()),
            forall|arena: &mut Memory, prev: usize, reference: usize, curr: usize, xor: bool, first: bool|
                (prev as int + 1) * 128 <= arena.words().len()
                && (reference as int + 1) * 128 <= arena.words().len()
                && (curr as int + 1) * 128 <= arena.words().len()
                && prev != curr && reference != curr
                ==> call_requires(fill, (arena, prev, reference, curr, xor, first)),
            forall|arena: &mut Memory, prev: usize, reference: usize, curr: usize, xor: bool, first: bool|
                call_ensures(fill, (arena, prev, reference, curr, xor, first), ())
                ==> (final(arena).words().len() == arena.words().len()
                    && final(arena).words() == memory::fill_result(
                        arena.words(), prev as int, reference as int, curr as int, xor)),
    ))]
    for index in starting_index..segment_length {
        #[cfg(verus_keep_ghost)]
        proof_decl! { let ghost before = memory.words(); }
        let (prev, curr) = crate::core_primitives::segment_base_positions(
            pass,
            slice,
            segment_length,
            lane_length,
            memory_blocks,
            lanes,
            lane,
            index,
        );
        let pseudo_rand = if data_independent {
            crate::core_address::scheduled_word(&mut input, &mut address, index)
        } else {
            memory.first_word(prev as usize)
        };
        #[cfg(verus_keep_ghost)]
        proof! {
            if data_independent {
                assert(input@ =~= core_address::address_input(
                    pass, lane, slice, memory_blocks, total_passes, algorithm as u32).update(6, input@[6]));
            }
            assert(pseudo_rand == segment_random(before, *seg, index)) by {
                reveal(segment_random);
            }
        }
        let reference = crate::core_primitives::segment_reference_position(
            pass,
            slice,
            segment_length,
            lane_length,
            memory_blocks,
            lanes,
            lane,
            index,
            pseudo_rand,
        );
        debug_assert!(lane_length == 4 * segment_length);
        debug_assert!(reference != curr && prev != curr);
        #[cfg(verus_keep_ghost)]
        proof! {
            assert((prev as usize as int + 1) * 128 <= memory.words().len());
            assert((reference as usize as int + 1) * 128 <= memory.words().len());
            assert((curr as usize as int + 1) * 128 <= memory.words().len());
            assert(prev as usize != curr as usize);
            assert(reference as usize != curr as usize);
            assert(call_requires(fill, (memory, prev as usize, reference as usize,
                curr as usize, with_xor, index == starting_index)));
        }
        fill(
            memory,
            prev as usize,
            reference as usize,
            curr as usize,
            with_xor,
            index == starting_index,
        );
        #[cfg(verus_keep_ghost)]
        proof! {
            core_address::schedule_successor(index);
            assert(memory.words() == segment_step(before, *seg, index)) by {
                reveal(segment_step);
            }
            segment_advance(initial, *seg, index);
        }
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    requires (prev as int + 1) * 128 <= old(memory).words().len(),
        (reference as int + 1) * 128 <= old(memory).words().len(),
        (curr as int + 1) * 128 <= old(memory).words().len(),
    ensures final(memory).words() == memory::fill_result(old(memory).words(),
        prev as int, reference as int, curr as int, with_xor),
        final(memory).words().len() == old(memory).words().len(),
))]
fn scalar_fill(
    memory: &mut Memory,
    prev: usize,
    reference: usize,
    curr: usize,
    with_xor: bool,
    _first: bool,
) {
    memory.fill_current(prev, reference, curr, with_xor);
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    requires seg.valid(), old(memory).words().len() == seg.memory_blocks as int * 128,
    ensures final(memory).words().len() == old(memory).words().len(),
        final(memory).words() == segment_prefix(old(memory).words(), *seg,
            (seg.segment_length as int - segment_start(*seg)) as nat),
))]
pub(crate) fn fill_segment_scalar(memory: &mut Memory, seg: &Segment) {
    walk_segment(memory, seg, scalar_fill);
}

#[cfg(verus_keep_ghost)]
verus! {
#[verifier::opaque]
// RFC 9106 section 3.2, steps 5-6: the lane segments within one slice.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub(crate) open spec fn slice_prefix(before: Seq<u64>, seg: Segment, lanes: nat) -> Seq<u64>
    decreases lanes,
{
    if lanes == 0 { before }
    else {
        let current = Segment { lane: (lanes - 1) as u32, ..seg };
        segment_prefix(slice_prefix(before, seg, (lanes - 1) as nat), current,
            (seg.segment_length as int - segment_start(current)) as nat)
    }
}

pub(crate) proof fn slice_advance(before: Seq<u64>, seg: Segment, lane: u32)
    ensures slice_prefix(before, seg, lane as nat + 1)
        == segment_prefix(slice_prefix(before, seg, lane as nat),
            Segment { lane, ..seg }, (seg.segment_length as int - segment_start(seg)) as nat),
{
    reveal(slice_prefix);
}
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires seg.valid(), old(memory).words().len() == seg.memory_blocks as int * 128,
    ensures final(memory).words().len() == old(memory).words().len(),
        final(memory).words() == slice_prefix(old(memory).words(), *seg, seg.lanes as nat),
))]
pub(crate) fn fill_slice(memory: &mut Memory, seg: &Segment) {
    #[cfg(verus_keep_ghost)]
    proof_decl! { let ghost initial = memory.words(); }
    #[cfg(verus_keep_ghost)]
    proof! { reveal(slice_prefix); }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant memory.words().len() == seg.memory_blocks as int * 128,
            memory.words() == slice_prefix(initial, *seg, lane as nat),
    ))]
    for lane in 0..seg.lanes {
        let current = Segment { lane, ..*seg };
        fill_segment_scalar(memory, &current);
        #[cfg(verus_keep_ghost)]
        proof! { slice_advance(initial, *seg, lane); }
    }
}

#[cfg(verus_keep_ghost)]
verus! {
#[verifier::opaque]
// RFC 9106 section 3.2, steps 5-6: the four slices within a pass.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub(crate) open spec fn pass_prefix(before: Seq<u64>, seg: Segment, slices: nat) -> Seq<u64>
    decreases slices,
{
    if slices == 0 { before }
    else {
        slice_prefix(pass_prefix(before, seg, (slices - 1) as nat),
            Segment { slice: (slices - 1) as u32, ..seg }, seg.lanes as nat)
    }
}

pub(crate) proof fn pass_advance(before: Seq<u64>, seg: Segment, slice: u32)
    ensures pass_prefix(before, seg, slice as nat + 1)
        == slice_prefix(pass_prefix(before, seg, slice as nat),
            Segment { slice, ..seg }, seg.lanes as nat),
{
    reveal(pass_prefix);
}

#[verifier::opaque]
// RFC 9106 section 3.2, steps 5-6: all requested passes.
// https://www.rfc-editor.org/rfc/rfc9106.html#section-3.2
pub(crate) open spec fn traversal_prefix(before: Seq<u64>, seg: Segment, passes: nat) -> Seq<u64>
    decreases passes,
{
    if passes == 0 { before }
    else {
        pass_prefix(traversal_prefix(before, seg, (passes - 1) as nat),
            Segment { pass: (passes - 1) as u32, ..seg }, 4)
    }
}

pub(crate) proof fn traversal_advance(before: Seq<u64>, seg: Segment, pass: u32)
    ensures traversal_prefix(before, seg, pass as nat + 1)
        == pass_prefix(traversal_prefix(before, seg, pass as nat),
            Segment { pass, ..seg }, 4),
{
    reveal(traversal_prefix);
}
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires seg.valid(), old(memory).words().len() == seg.memory_blocks as int * 128,
    ensures final(memory).words().len() == old(memory).words().len(),
        final(memory).words() == pass_prefix(old(memory).words(), *seg, 4),
))]
pub(crate) fn fill_pass(memory: &mut Memory, seg: &Segment) {
    #[cfg(verus_keep_ghost)]
    proof_decl! { let ghost initial = memory.words(); }
    #[cfg(verus_keep_ghost)]
    proof! { reveal(pass_prefix); }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant memory.words().len() == seg.memory_blocks as int * 128,
            memory.words() == pass_prefix(initial, *seg, slice as nat),
    ))]
    for slice in 0..4u32 {
        let current = Segment { slice, ..*seg };
        fill_slice(memory, &current);
        #[cfg(verus_keep_ghost)]
        proof! { pass_advance(initial, *seg, slice); }
    }
}

#[cfg_attr(verus_keep_ghost, verifier::loop_isolation(false))]
#[cfg_attr(verus_keep_ghost, verus_spec(
    requires seg.valid(), old(memory).words().len() == seg.memory_blocks as int * 128,
    ensures final(memory).words().len() == old(memory).words().len(),
        final(memory).words() == traversal_prefix(old(memory).words(), *seg, seg.total_passes as nat),
))]
pub(crate) fn fill_memory(memory: &mut Memory, seg: &Segment) {
    #[cfg(verus_keep_ghost)]
    proof_decl! { let ghost initial = memory.words(); }
    #[cfg(verus_keep_ghost)]
    proof! { reveal(traversal_prefix); }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant memory.words().len() == seg.memory_blocks as int * 128,
            memory.words() == traversal_prefix(initial, *seg, pass as nat),
    ))]
    for pass in 0..seg.total_passes {
        let current = Segment { pass, ..*seg };
        fill_pass(memory, &current);
        #[cfg(verus_keep_ghost)]
        proof! { traversal_advance(initial, *seg, pass); }
    }
}
