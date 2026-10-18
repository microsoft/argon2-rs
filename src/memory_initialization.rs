#[cfg(verus_keep_ghost)]
use crate::memory_initialization_model as model;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires column < 2,
    ensures result@ == model::seed(h0@, column, lane),
))]
pub(crate) fn seed(h0: &[u8; 64], column: u32, lane: u32) -> [u8; 72] {
    let column_bytes = crate::blake2b::h_prime_length(column);
    let lane_bytes = crate::blake2b::h_prime_length(lane);
    let mut output = [0u8; 72];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant column < 2,
            column_bytes@ == crate::blake2b_long_model::length_prefix(column),
            lane_bytes@ == crate::blake2b_long_model::length_prefix(lane),
            forall|position: int| 0 <= position < 72 ==>
            output@[position] == if position < index as int {
                model::seed(h0@, column, lane)[position]
            } else { 0u8 },
        decreases 72 - index,
    ))]
    for index in 0..72 {
        output[index] = if index < 64 {
            h0[index]
        } else if index < 68 {
            column_bytes[index - 64]
        } else {
            lane_bytes[index - 68]
        };
    }
    output
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires bytes.len() == 1024,
    ensures result@ == model::decode(bytes@),
))]
pub(crate) fn decode(bytes: &[u8]) -> [u64; 128] {
    let mut output = [0u64; 128];
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant bytes.len() == 1024,
            forall|position: int| 0 <= position < 128 ==>
            output@[position] == if position < index as int {
                model::decode(bytes@)[position]
            } else { 0u64 },
        decreases 128 - index,
    ))]
    for index in 0..128 {
        let start = 8 * index;
        output[index] = (bytes[start] as u64)
            | ((bytes[start + 1] as u64) << 8)
            | ((bytes[start + 2] as u64) << 16)
            | ((bytes[start + 3] as u64) << 24)
            | ((bytes[start + 4] as u64) << 32)
            | ((bytes[start + 5] as u64) << 40)
            | ((bytes[start + 6] as u64) << 48)
            | ((bytes[start + 7] as u64) << 56);
    }
    output
}

#[cfg_attr(verus_keep_ghost, verus_spec(result =>
    requires column < 2,
    ensures result@ == model::block(h0@, column, lane),
))]
pub(crate) fn block(h0: &[u8; 64], column: u32, lane: u32) -> [u64; 128] {
    let input = crate::wipe::Bytes(seed(h0, column, lane));
    let input_slice: &[u8] = &input.0;
    let parts: [&[u8]; 1] = [input_slice];
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(crate::blake2b_update_model::blake2b_parts_prefix);
        assert(crate::blake2b_update_model::blake2b_parts_prefix(parts@, 0) == Seq::empty());
        assert(crate::blake2b_update_model::blake2b_parts_prefix(parts@, 1) == input_slice@);
    }
    let bytes = crate::wipe::ByteVec(crate::blake2b::blake2b_long(1024, &parts));
    let output = decode(&bytes.0);
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(model::block);
    }
    output
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    requires 128 * (slot as int + 1) <= old(memory)@.len(),
    ensures final(memory)@ == model::write_prefix(old(memory)@, 128 * slot as int, output@, 128),
))]
pub(crate) fn write_block(memory: &mut [u64], slot: usize, output: &[u64; 128]) {
    let _length = memory.len();
    let start = 128 * slot;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            memory.len() == _length,
            start as int + 128 <= _length,
            memory@ == model::write_prefix(old(memory)@, start as int, output@, index as nat),
        decreases 128 - index,
    ))]
    for index in 0..128 {
        memory[start + index] = output[index];
    }
}

#[cfg_attr(verus_keep_ghost, verus_spec(
    requires lanes > 0, lane_length >= 2,
        lanes as int * lane_length as int <= u32::MAX as int,
        lanes as int * lane_length as int * 128 == old(memory)@.len(),
    ensures final(memory)@.len() == old(memory)@.len(),
        final(memory)@ == model::initialized_prefix(
        old(memory)@, h0@, lane_length as nat, 2 * lanes as nat),
))]
pub(crate) fn initialize_words(memory: &mut [u64], h0: &[u8; 64], lanes: u32, lane_length: u32) {
    let _length = memory.len();
    #[cfg(verus_keep_ghost)]
    proof! {
        reveal(model::initialized_prefix);
    }
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            lanes > 0, lane_length >= 2,
            lanes as int * lane_length as int <= u32::MAX as int,
            lanes as int * lane_length as int * 128 == _length,
            memory.len() == _length,
            old(memory)@.len() == _length,
            memory@ == model::initialized_prefix(old(memory)@, h0@, lane_length as nat, 2 * lane as nat),
        decreases lanes - lane,
    ))]
    for lane in 0..lanes {
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant
                lanes > 0, lane < lanes, lane_length >= 2,
                lanes as int * lane_length as int <= u32::MAX as int,
                lanes as int * lane_length as int * 128 == _length,
                memory.len() == _length,
                old(memory)@.len() == _length,
                memory@ == model::initialized_prefix(old(memory)@, h0@, lane_length as nat,
                    2 * lane as nat + column as nat),
            decreases 2 - column,
        ))]
        for column in 0..2u32 {
            #[cfg(verus_keep_ghost)]
            proof! {
                assert((2 * lane as int + column as int + 2) / 2 == lane as int + 1);
                assert((lane as int + 1) * lane_length as int * 128
                    <= lanes as int * lane_length as int * 128) by(nonlinear_arith)
                    requires lane < lanes, lane_length >= 2;
                model::prefix_step(old(memory)@, h0@, lane_length as nat,
                    2 * lane as nat + column as nat);
                assert((lane as int * lane_length as int + column as int)
                    < (lanes as int * lane_length as int)) by(nonlinear_arith)
                    requires lane < lanes, lane_length >= 2, 0 <= column < 2;
            }
            let output = crate::wipe::Words(block(h0, column, lane));
            write_block(memory, (lane * lane_length + column) as usize, &output.0);
        }
    }
    #[cfg(verus_keep_ghost)]
    proof! { assert(memory@.len() == old(memory)@.len()); }
}

#[cfg(test)]
mod tests {
    #[test]
    fn seed_and_decoder_match_standard_encoding() {
        let h0 = core::array::from_fn(|index| index as u8);
        for column in 0..2 {
            for lane in [0u32, 1, 0x0403_0201, u32::MAX] {
                let encoded = super::seed(&h0, column, lane);
                assert_eq!(&encoded[..64], &h0);
                assert_eq!(&encoded[64..68], &column.to_le_bytes());
                assert_eq!(&encoded[68..72], &lane.to_le_bytes());
            }
        }
        let bytes: [u8; 1024] = core::array::from_fn(|index| index as u8);
        let decoded = super::decode(&bytes);
        for index in 0..128 {
            assert_eq!(
                decoded[index],
                u64::from_le_bytes(bytes[8 * index..8 * index + 8].try_into().unwrap())
            );
        }
    }

    #[test]
    fn initialize_preserves_unwritten_slots() {
        let h0 = [0x5au8; 64];
        for lanes in 1..=4u32 {
            for lane_length in [2u32, 8, 12] {
                let mut arena =
                    vec![0x1234_5678_9abc_def0u64; (lanes * lane_length) as usize * 128];
                super::initialize_words(&mut arena, &h0, lanes, lane_length);
                for lane in 0..lanes {
                    for column in 0..lane_length {
                        let start = (lane * lane_length + column) as usize * 128;
                        if column < 2 {
                            assert_eq!(
                                &arena[start..start + 128],
                                &super::block(&h0, column, lane)
                            );
                        } else {
                            assert_eq!(
                                &arena[start..start + 128],
                                &[0x1234_5678_9abc_def0u64; 128]
                            );
                        }
                    }
                }
            }
        }
    }
}
