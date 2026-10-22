//! Scalar core primitives for parameter checks, memory geometry, and indexing.
//!
//! These canonical executable leaves are shared by Cargo and Verus. Verus
//! checks their contracts individually; this is not a proof of the full hash
//! loop or of every caller satisfying those contracts.

#[cfg(verus_keep_ghost)]
use crate::{proofs, specs};
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result == specs::valid_params(lanes, memory, passes),
))]
pub fn valid_params(lanes: u32, memory: u32, passes: u32) -> bool {
    lanes >= 1 && lanes <= 0x00ff_ffff && memory >= 8 * lanes && passes >= 1
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires specs::valid_params(lanes, memory, 1),
    ensures result.0 == specs::memory_blocks(memory, lanes),
        result.1 == result.0 / lanes,
        result.2 == result.1 / 4,
        result.1 == 4 * result.2,
        result.1 == 4 * result.2,
        result.2 >= 2,
        result.0 as int == lanes as int * result.1 as int,
        result.1 >= 8,
))]
pub fn memory_geometry(memory: u32, lanes: u32) -> (u32, u32, u32) {
    let quantum = 4 * lanes;
    let segment = memory / quantum;
    #[cfg(verus_keep_ghost)]
    proof! {
        proofs::geometry(memory, lanes, quantum, segment);
        assert(segment as int * quantum as int == lanes as int * (segment as int * 4))
            by(nonlinear_arith) requires quantum == 4 * lanes;
    }
    let blocks = segment * quantum;
    (blocks, segment * 4, segment)
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires lane_length >= 2, current < lane_length,
    ensures result < lane_length, result != current,
        result == if current == 0 { lane_length - 1 } else { current - 1 },
))]
pub fn previous_index(current: u32, lane_length: u32) -> u32 {
    if current == 0 {
        lane_length - 1
    } else {
        current - 1
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result == (algorithm == 1 || (algorithm == 2 && pass == 0 && slice < 2)),
))]
pub fn uses_independent_addresses(algorithm: u32, pass: u32, slice: u32) -> bool {
    algorithm == 1 || (algorithm == 2 && pass == 0 && slice < 2)
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    ensures result == (version == 0x13 && pass > 0),
))]
pub fn xor_on_pass(version: u32, pass: u32) -> bool {
    version == 0x13 && pass > 0
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires specs::valid_position(pass, slice, segment, index),
    ensures result as int == specs::reference_area(pass, slice, segment, index, same_lane),
        1 <= result < 4 * segment,
))]
pub fn reference_area(pass: u32, slice: u32, segment: u32, index: u32, same_lane: bool) -> u32 {
    #[cfg(verus_keep_ghost)]
    proof! { proofs::position_bounds(slice, segment, index); }
    if pass == 0 {
        if slice == 0 {
            index - 1
        } else if same_lane {
            slice * segment + index - 1
        } else {
            slice * segment - if index == 0 { 1 } else { 0 }
        }
    } else if same_lane {
        3 * segment + index - 1
    } else {
        3 * segment - if index == 0 { 1 } else { 0 }
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires specs::valid_position(pass, slice, segment, index),
    ensures result as int == specs::index_alpha(pass, slice, segment, index, j1, same_lane),
    result < 4 * segment,
    same_lane ==> result as int != slice as int * segment as int + index as int,
))]
pub fn index_alpha(
    pass: u32,
    slice: u32,
    segment: u32,
    index: u32,
    j1: u32,
    same_lane: bool,
) -> u32 {
    let area = reference_area(pass, slice, segment, index, same_lane) as u64;
    let rand = j1 as u64;
    #[cfg(verus_keep_ghost)]
    proof! { proofs::square_bound(rand); }
    let square = rand * rand;
    let high = square / 0x1_0000_0000;
    #[cfg(verus_keep_ghost)]
    proof! { proofs::product_bound(area, square, high); }
    let product = area * high;
    let scaled = product / 0x1_0000_0000;
    #[cfg(verus_keep_ghost)]
    proof! { proofs::scaled_bound(area, high, product, scaled); }
    let relative = area - 1 - scaled;
    #[cfg(verus_keep_ghost)]
    proof! { proofs::position_bounds(slice, segment, index); }
    let start = if pass != 0 && slice != 3 { ((slice + 1) * segment) as u64 } else { 0u64 };
    let lane = (4 * segment) as u64;
    let mapped = (start + relative) % lane;
    #[cfg(verus_keep_ghost)]
    proof! {
        proofs::mapped_bound((start + relative) as u64, lane);
        if same_lane {
            proofs::index_alpha_excludes_current(pass, slice, segment, index, j1);
        }
    }
    mapped as u32
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires lanes > 0, lane < lanes, slice < 4,
        lane_length == 4 * segment_length,
        memory_blocks as int == lanes as int * lane_length as int,
        specs::valid_position(pass, slice, segment_length, index),
    ensures result.0 < memory_blocks, result.1 < memory_blocks,
        result.0 != result.1,
        result.0 as int == specs::predecessor_position(
            lane, lane_length, slice, segment_length, index),
        result.1 as int == lane as int * lane_length as int
            + slice as int * segment_length as int + index as int,
))]
#[cfg_attr(not(verus_keep_ghost), allow(unused_variables))]
pub fn segment_base_positions(
    pass: u32,
    slice: u32,
    segment_length: u32,
    lane_length: u32,
    memory_blocks: u32,
    lanes: u32,
    lane: u32,
    index: u32,
) -> (u32, u32) {
    #[cfg(verus_keep_ghost)]
    proof! {
        assert((slice as int * segment_length as int + index as int) < lane_length as int)
            by(nonlinear_arith) requires
                slice < 4, index < segment_length,
                lane_length == 4 * segment_length;
    }
    let curr_index = slice * segment_length + index;
    let prev_index = previous_index(curr_index, lane_length);
    #[cfg(verus_keep_ghost)]
    proof! {
        assert((lane as int * lane_length as int + curr_index as int) < memory_blocks as int)
            by(nonlinear_arith) requires
                lane < lanes, curr_index < lane_length,
                memory_blocks as int == lanes as int * lane_length as int,
                0 < lane_length;
        assert((lane as int * lane_length as int + prev_index as int) < memory_blocks as int)
            by(nonlinear_arith) requires
                lane < lanes, prev_index < lane_length,
                memory_blocks as int == lanes as int * lane_length as int,
                0 < lane_length;
    }
    let curr_pos = lane * lane_length + curr_index;
    let prev_pos = lane * lane_length + prev_index;
    (prev_pos, curr_pos)
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires lanes > 0, lane < lanes, slice < 4,
        lane_length == 4 * segment_length,
        memory_blocks as int == lanes as int * lane_length as int,
        specs::valid_position(pass, slice, segment_length, index),
    ensures result < memory_blocks,
        result as int == specs::reference_position(
            pass, slice, segment_length, lane_length, lanes, lane, index, pseudo_rand),
        result as int != lane as int * lane_length as int
            + slice as int * segment_length as int + index as int,
))]
#[cfg_attr(not(verus_keep_ghost), allow(unused_variables))]
pub fn segment_reference_position(
    pass: u32,
    slice: u32,
    segment_length: u32,
    lane_length: u32,
    memory_blocks: u32,
    lanes: u32,
    lane: u32,
    index: u32,
    pseudo_rand: u64,
) -> u32 {
    let mut ref_lane = ((pseudo_rand >> 32) as u32) % lanes;
    if pass == 0 && slice == 0 {
        ref_lane = lane;
    }
    let same_lane = ref_lane == lane;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert((slice as int * segment_length as int + index as int) < lane_length as int)
            by(nonlinear_arith) requires
                slice < 4, index < segment_length,
                lane_length == 4 * segment_length;
    }
    let curr_index = slice * segment_length + index;
    #[cfg(verus_keep_ghost)]
    proof! {
        assert(curr_index < lane_length);
        assert((lane as int * lane_length as int + curr_index as int) < memory_blocks as int)
            by(nonlinear_arith) requires
                lane < lanes, curr_index < lane_length,
                memory_blocks as int == lanes as int * lane_length as int,
                lane_length > 0;
    }
    let ref_index = index_alpha(pass, slice, segment_length, index, pseudo_rand as u32, same_lane);
    #[cfg(verus_keep_ghost)]
    proof! {
        assert((ref_lane as int * lane_length as int + ref_index as int) < memory_blocks as int)
            by(nonlinear_arith) requires
                ref_lane < lanes, ref_index < lane_length,
                memory_blocks as int == lanes as int * lane_length as int,
                0 < lane_length;
    }
    let ref_pos = ref_lane * lane_length + ref_index;
    let curr_pos = lane * lane_length + curr_index;
    #[cfg(verus_keep_ghost)]
    proof! {
        if same_lane {
            assert(ref_pos != curr_pos) by(nonlinear_arith) requires
                ref_pos as int == ref_lane as int * lane_length as int + ref_index as int,
                curr_pos as int == lane as int * lane_length as int + curr_index as int,
                ref_lane == lane, ref_index as int != curr_index as int;
        } else {
            assert(ref_pos != curr_pos) by(nonlinear_arith) requires
                ref_pos as int == ref_lane as int * lane_length as int + ref_index as int,
                curr_pos as int == lane as int * lane_length as int + curr_index as int,
                ref_lane != lane,
                ref_lane < lanes, lane < lanes,
                ref_index < lane_length, curr_index < lane_length;
        }
    }
    ref_pos
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_and_validation_boundaries() {
        for lanes in [1, 2, 3, 4, 0x00ff_ffff] {
            for memory in [8 * lanes, 8 * lanes + 1, u32::MAX] {
                assert!(valid_params(lanes, memory, 1));
                let (blocks, lane, segment) = memory_geometry(memory, lanes);
                let expected = (memory as u64 / (4 * lanes as u64)) * (4 * lanes as u64);
                assert_eq!(blocks as u64, expected);
                assert_eq!(lane, segment * 4);
                assert!(segment >= 2);
                assert!(!valid_params(lanes, memory, 0));
            }
        }
        assert!(!valid_params(0, u32::MAX, 1));
        assert!(!valid_params(1 << 24, u32::MAX, 1));
    }

    #[test]
    fn reference_index_matches_wide_arithmetic_and_excludes_current() {
        for segment in [2u32, 3, 8, 32, 8192, 0x3fff_ffff] {
            for pass in [0u32, 1, 2, u32::MAX] {
                for slice in 0..4u32 {
                    for index in [0u32, 1, segment / 2, segment - 1] {
                        if pass == 0 && slice == 0 && index < 2 {
                            continue;
                        }
                        for same_lane in [false, true] {
                            for random in [0u32, 1, 0x7fff_ffff, 0xffff_fffe, u32::MAX] {
                                let lane = 4 * segment as u128;
                                let area = if pass == 0 {
                                    if slice == 0 {
                                        index as u128 - 1
                                    } else if same_lane {
                                        slice as u128 * segment as u128 + index as u128 - 1
                                    } else {
                                        slice as u128 * segment as u128 - u128::from(index == 0)
                                    }
                                } else {
                                    lane - segment as u128
                                        + if same_lane { index as u128 } else { 0 }
                                        - u128::from(same_lane || index == 0)
                                };
                                let quadratic = (random as u128 * random as u128) >> 32;
                                let relative = area - 1 - ((area * quadratic) >> 32);
                                let start = if pass > 0 {
                                    ((slice as u128 + 1) % 4) * segment as u128
                                } else {
                                    0
                                };
                                let result =
                                    index_alpha(pass, slice, segment, index, random, same_lane);
                                assert_eq!(result as u128, (start + relative) % lane);
                                if same_lane {
                                    assert_ne!(result, slice * segment + index);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
