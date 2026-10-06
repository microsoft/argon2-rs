use vstd::prelude::*;

verus! {

pub open spec fn blamka(x: u64, y: u64) -> u64 {
    ((x as int + y as int + 2 * (x % 0x1_0000_0000) as int
        * (y % 0x1_0000_0000) as int) % 0x1_0000_0000_0000_0000) as u64
}

pub open spec fn rotate(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

pub open spec fn gb(a: u64, b: u64, c: u64, d: u64) -> (u64, u64, u64, u64) {
    let a = blamka(a, b);
    let d = rotate(d ^ a, 32);
    let c = blamka(c, d);
    let b = rotate(b ^ c, 24);
    let a = blamka(a, b);
    let d = rotate(d ^ a, 16);
    let c = blamka(c, d);
    let b = rotate(b ^ c, 63);
    (a, b, c, d)
}

pub open spec fn permute(v: Seq<u64>) -> Seq<u64>
    recommends v.len() == 16,
{
    let (v0, v4, v8, v12) = gb(v[0], v[4], v[8], v[12]);
    let (v1, v5, v9, v13) = gb(v[1], v[5], v[9], v[13]);
    let (v2, v6, v10, v14) = gb(v[2], v[6], v[10], v[14]);
    let (v3, v7, v11, v15) = gb(v[3], v[7], v[11], v[15]);
    let (v0, v5, v10, v15) = gb(v0, v5, v10, v15);
    let (v1, v6, v11, v12) = gb(v1, v6, v11, v12);
    let (v2, v7, v8, v13) = gb(v2, v7, v8, v13);
    let (v3, v4, v9, v14) = gb(v3, v4, v9, v14);
    seq![v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15]
}

pub open spec fn blake2b_add(x: u64, y: u64) -> u64 {
    ((x as int + y as int) % 0x1_0000_0000_0000_0000) as u64
}

pub open spec fn blake2b_iv() -> Seq<u64> {
    seq![
        0x6a09e667f3bcc908u64, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]
}

pub open spec fn blake2b_sigma() -> Seq<[usize; 16]> {
    seq![
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ]
}

pub open spec fn blake2b_g(
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    x: u64,
    y: u64,
) -> (u64, u64, u64, u64) {
    let a = blake2b_add(blake2b_add(a, b), x);
    let d = rotate(d ^ a, 32);
    let c = blake2b_add(c, d);
    let b = rotate(b ^ c, 24);
    let a = blake2b_add(blake2b_add(a, b), y);
    let d = rotate(d ^ a, 16);
    let c = blake2b_add(c, d);
    let b = rotate(b ^ c, 63);
    (a, b, c, d)
}

pub open spec fn blake2b_g_update(
    state: Seq<u64>,
    a_index: int,
    b_index: int,
    c_index: int,
    d_index: int,
    x: u64,
    y: u64,
) -> Seq<u64>
    recommends state.len() == 16,
        0 <= a_index < 16, 0 <= b_index < 16,
        0 <= c_index < 16, 0 <= d_index < 16,
        a_index != b_index, a_index != c_index, a_index != d_index,
        b_index != c_index, b_index != d_index, c_index != d_index,
{
    let (a, b, c, d) = blake2b_g(
        state[a_index], state[b_index], state[c_index], state[d_index], x, y,
    );
    state.update(a_index, a)
        .update(b_index, b)
        .update(c_index, c)
        .update(d_index, d)
}

pub open spec fn valid_blake2b_round_sigma(sigma: Seq<usize>) -> bool
    recommends sigma.len() == 16,
{
    forall|i: int| 0 <= i < 16 ==> #[trigger] sigma[i] < 16
}

pub open spec fn valid_blake2b_sigma(sigma: Seq<[usize; 16]>) -> bool
    recommends sigma.len() == 12,
{
    forall|r: int| 0 <= r < 12 ==> #[trigger] valid_blake2b_round_sigma(sigma[r]@)
}

pub open spec fn blake2b_round(
    state: Seq<u64>,
    message: Seq<u64>,
    sigma: Seq<usize>,
) -> Seq<u64>
    recommends state.len() == 16, message.len() == 16,
        valid_blake2b_round_sigma(sigma),
{
    let v = blake2b_g_update(state, 0, 4, 8, 12, message[sigma[0] as int], message[sigma[1] as int]);
    let v = blake2b_g_update(v, 1, 5, 9, 13, message[sigma[2] as int], message[sigma[3] as int]);
    let v = blake2b_g_update(v, 2, 6, 10, 14, message[sigma[4] as int], message[sigma[5] as int]);
    let v = blake2b_g_update(v, 3, 7, 11, 15, message[sigma[6] as int], message[sigma[7] as int]);
    let v = blake2b_g_update(v, 0, 5, 10, 15, message[sigma[8] as int], message[sigma[9] as int]);
    let v = blake2b_g_update(v, 1, 6, 11, 12, message[sigma[10] as int], message[sigma[11] as int]);
    let v = blake2b_g_update(v, 2, 7, 8, 13, message[sigma[12] as int], message[sigma[13] as int]);
    blake2b_g_update(v, 3, 4, 9, 14, message[sigma[14] as int], message[sigma[15] as int])
}

pub open spec fn blake2b_initial_v(
    h: Seq<u64>,
    iv: Seq<u64>,
    counter: u128,
    last: bool,
) -> Seq<u64>
    recommends h.len() == 8, iv.len() == 8,
{
    let v = Seq::new(16, |i: int| if i < 8 { h[i] } else { iv[i - 8] });
    let v = v.update(12, v[12] ^ (counter as u64));
    let v = v.update(13, v[13] ^ ((counter >> 64) as u64));
    if last { v.update(14, !v[14]) } else { v }
}

pub open spec fn blake2b_rounds_prefix(
    state: Seq<u64>,
    message: Seq<u64>,
    sigma: Seq<[usize; 16]>,
    completed: nat,
) -> Seq<u64>
    recommends state.len() == 16, message.len() == 16, sigma.len() == 12,
        completed <= 12, valid_blake2b_sigma(sigma),
    decreases completed,
{
    if completed == 0 {
        state
    } else {
        blake2b_round(
            blake2b_rounds_prefix(state, message, sigma, (completed - 1nat) as nat),
            message,
            sigma[(completed - 1nat) as int]@,
        )
    }
}

pub open spec fn blake2b_fold(h: Seq<u64>, state: Seq<u64>) -> Seq<u64>
    recommends h.len() == 8, state.len() == 16,
{
    Seq::new(8, |i: int| h[i] ^ state[i] ^ state[i + 8])
}

pub open spec fn blake2b_rfc_compress_state(
    h: Seq<u64>,
    message: Seq<u64>,
    counter: u128,
    last: bool,
) -> Seq<u64> {
    blake2b_compress_state(
        h, message, counter, last, blake2b_iv(), blake2b_sigma(),
    )
}

pub open spec fn blake2b_decode_block(block: Seq<u8>) -> Seq<u64>
    recommends block.len() == 128,
{
    Seq::new(16, |i: int| {
        (block[8 * i] as u64)
            | ((block[8 * i + 1] as u64) << 8)
            | ((block[8 * i + 2] as u64) << 16)
            | ((block[8 * i + 3] as u64) << 24)
            | ((block[8 * i + 4] as u64) << 32)
            | ((block[8 * i + 5] as u64) << 40)
            | ((block[8 * i + 6] as u64) << 48)
            | ((block[8 * i + 7] as u64) << 56)
    })
}

pub open spec fn blake2b_compress_block(
    h: Seq<u64>,
    block: Seq<u8>,
    counter: u128,
    last: bool,
) -> Seq<u64>
    recommends h.len() == 8, block.len() == 128,
{
    blake2b_rfc_compress_state(h, blake2b_decode_block(block), counter, last)
}

pub open spec fn blake2b_pad_final_block(buffer: Seq<u8>, buffered_len: nat) -> Seq<u8>
    recommends buffer.len() == 128, buffered_len <= 128,
{
    Seq::new(128, |i: int| if i < buffered_len { buffer[i] } else { 0u8 })
}

pub open spec fn blake2b_serialize_state(state: Seq<u64>) -> Seq<u8>
    recommends state.len() == 8,
{
    Seq::new(64, |i: int| (state[i / 8] >> (8 * (i % 8))) as u8)
}

pub open spec fn blake2b_finalize_result(
    h: Seq<u64>,
    counter: u128,
    buffer: Seq<u8>,
    buffered_len: nat,
) -> Seq<u8>
    recommends h.len() == 8, buffer.len() == 128, buffered_len <= 128,
        counter as int + buffered_len as int <= u128::MAX as int,
{
    let block = blake2b_pad_final_block(buffer, buffered_len);
    let state = blake2b_compress_block(
        h, block, (counter as int + buffered_len as int) as u128, true,
    );
    blake2b_serialize_state(state)
}

pub open spec fn blake2b_buffer_append_prefix(
    before: Seq<u8>,
    start: int,
    data: Seq<u8>,
    copied: int,
) -> Seq<u8>
    recommends before.len() == 128, 0 <= start <= 128,
        start + data.len() <= 128, 0 <= copied <= data.len(),
{
    Seq::new(128, |i: int| {
        if start <= i && i < start + copied {
            data[i - start]
        } else {
            before[i]
        }
    })
}

pub open spec fn blake2b_buffer_append(
    before: Seq<u8>,
    start: int,
    data: Seq<u8>,
) -> Seq<u8>
    recommends before.len() == 128, 0 <= start <= 128,
        start + data.len() <= 128,
{
    blake2b_buffer_append_prefix(before, start, data, data.len() as int)
}

pub open spec fn blake2b_update_take(buffered_len: nat, input_len: nat) -> nat
    recommends buffered_len <= 128,
{
    let available = (128nat - buffered_len) as nat;
    if input_len < available { input_len } else { available }
}

pub open spec fn blake2b_update_step(
    h: Seq<u64>,
    counter: u128,
    buffer: Seq<u8>,
    buffered_len: nat,
    input: Seq<u8>,
) -> (Seq<u64>, u128, Seq<u8>, nat, nat)
    recommends h.len() == 8, buffer.len() == 128,
        buffered_len <= 128, input.len() > 0,
        counter as int + buffered_len as int + input.len() as int <= u128::MAX as int,
        buffered_len < 128 || counter <= u128::MAX - 128,
{
    let (next_h, next_counter, next_len) = if buffered_len == 128 {
        (
            blake2b_compress_block(h, buffer, (counter as int + 128) as u128, false),
            (counter as int + 128) as u128,
            0nat,
        )
    } else {
        (h, counter, buffered_len)
    };
    let take = blake2b_update_take(next_len, input.len());
    let chunk = Seq::new(take, |i: int| input[i]);
    let next_buffer = blake2b_buffer_append(buffer, next_len as int, chunk);
    (next_h, next_counter, next_buffer, next_len + take, take)
}

pub open spec fn blake2b_compress_state(
    h: Seq<u64>,
    message: Seq<u64>,
    counter: u128,
    last: bool,
    iv: Seq<u64>,
    sigma: Seq<[usize; 16]>,
) -> Seq<u64>
    recommends h.len() == 8, message.len() == 16, iv.len() == 8,
        sigma.len() == 12, valid_blake2b_sigma(sigma),
{
    let initial = blake2b_initial_v(h, iv, counter, last);
    let state = blake2b_rounds_prefix(initial, message, sigma, 12);
    blake2b_fold(h, state)
}

pub open spec fn gather_row(words: Seq<u64>, row: int) -> Seq<u64>
    recommends words.len() == 128, 0 <= row < 8,
{
    Seq::new(16, |i: int| words[16 * row + i])
}

pub open spec fn scatter_row_prefix(
    before: Seq<u64>,
    row: int,
    completed_words: int,
    output: Seq<u64>,
) -> Seq<u64>
    recommends before.len() == 128, output.len() == 16,
        0 <= row < 8, 0 <= completed_words <= 16,
{
    Seq::new(128, |i: int| {
        if i / 16 == row && i % 16 < completed_words {
            output[i % 16]
        } else {
            before[i]
        }
    })
}

pub open spec fn permute_one_row(words: Seq<u64>, row: int) -> Seq<u64>
    recommends words.len() == 128, 0 <= row < 8,
{
    scatter_row_prefix(words, row, 16, permute(gather_row(words, row)))
}

pub open spec fn permute_rows_prefix(words: Seq<u64>, completed: nat) -> Seq<u64>
    recommends words.len() == 128, completed <= 8,
    decreases completed,
{
    if completed == 0 {
        words
    } else {
        permute_one_row(
            permute_rows_prefix(words, (completed - 1nat) as nat),
            (completed - 1nat) as int,
        )
    }
}

pub open spec fn gather_column(words: Seq<u64>, column: int) -> Seq<u64>
    recommends words.len() == 128, 0 <= column < 8,
{
    Seq::new(16, |i: int| words[16 * (i / 2) + 2 * column + i % 2])
}

pub open spec fn scatter_column_prefix(
    before: Seq<u64>,
    column: int,
    completed_rows: int,
    output: Seq<u64>,
) -> Seq<u64>
    recommends before.len() == 128, output.len() == 16,
        0 <= column < 8, 0 <= completed_rows <= 8,
{
    Seq::new(128, |i: int| {
        let row = i / 16;
        let col = (i % 16) / 2;
        let half = i % 2;
        if col == column && row < completed_rows {
            output[2 * row + half]
        } else {
            before[i]
        }
    })
}

pub open spec fn permute_one_column(words: Seq<u64>, column: int) -> Seq<u64>
    recommends words.len() == 128, 0 <= column < 8,
{
    scatter_column_prefix(words, column, 8, permute(gather_column(words, column)))
}

pub open spec fn permute_columns_prefix(words: Seq<u64>, completed: nat) -> Seq<u64>
    recommends words.len() == 128, completed <= 8,
    decreases completed,
{
    if completed == 0 {
        words
    } else {
        permute_one_column(
            permute_columns_prefix(words, (completed - 1nat) as nat),
            (completed - 1nat) as int,
        )
    }
}

pub open spec fn xor_words_prefix(
    left: Seq<u64>,
    right: Seq<u64>,
    completed: int,
) -> Seq<u64>
    recommends left.len() == 128, right.len() == 128, 0 <= completed <= 128,
{
    Seq::new(128, |i: int| {
        if i < completed {
            left[i] ^ right[i]
        } else {
            left[i]
        }
    })
}

pub open spec fn xor_words(left: Seq<u64>, right: Seq<u64>) -> Seq<u64>
    recommends left.len() == 128, right.len() == 128,
{
    Seq::new(128, |i: int| left[i] ^ right[i])
}

pub open spec fn replace_prefix(
    before: Seq<u64>,
    replacement: Seq<u64>,
    completed: int,
) -> Seq<u64>
    recommends before.len() == 128, replacement.len() == 128,
        0 <= completed <= 128,
{
    Seq::new(128, |i: int| if i < completed { replacement[i] } else { before[i] })
}

pub open spec fn fill_block_result(
    prev: Seq<u64>,
    reference: Seq<u64>,
    old_next: Seq<u64>,
    with_xor: bool,
) -> Seq<u64>
    recommends prev.len() == 128, reference.len() == 128, old_next.len() == 128,
{
    let r = xor_words(prev, reference);
    let tmp = if with_xor { xor_words(r, old_next) } else { r };
    xor_words(tmp, permute_columns_prefix(permute_rows_prefix(r, 8), 8))
}

pub open spec fn valid_params(lanes: u32, memory: u32, passes: u32) -> bool {
    1 <= lanes <= 0x00ff_ffff && 8 * lanes <= memory && passes >= 1
}

pub open spec fn memory_blocks(memory: u32, lanes: u32) -> int {
    (memory as int / (4 * lanes)) * (4 * lanes)
}

pub open spec fn valid_position(pass: u32, slice: u32, segment: u32, index: u32) -> bool {
    2 <= segment <= 0x3fff_ffff && slice < 4 && index < segment
        && (pass == 0 && slice == 0 ==> index >= 2)
}

pub open spec fn reference_area(pass: u32, slice: u32, segment: u32, index: u32, same_lane: bool) -> int {
    if pass == 0 {
        if slice == 0 { index as int - 1 }
        else if same_lane { slice * segment + index - 1 }
        else { slice * segment - if index == 0 { 1int } else { 0int } }
    } else if same_lane { 3 * segment + index - 1 }
    else { 3 * segment - if index == 0 { 1int } else { 0int } }
}

pub open spec fn index_alpha(pass: u32, slice: u32, segment: u32, index: u32, j1: u32, same_lane: bool) -> int {
    let area = reference_area(pass, slice, segment, index, same_lane);
    let relative = area - 1 - (area * ((j1 as int * j1 as int) / 0x1_0000_0000)) / 0x1_0000_0000;
    let start = if pass != 0 && slice != 3 { (slice + 1) * segment } else { 0int };
    (start + relative) % (4 * segment)
}

}
