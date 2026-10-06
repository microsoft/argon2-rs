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

pub open spec fn permute_rows_prefix(
    before: Seq<[u64; 16]>,
    after: Seq<[u64; 16]>,
    completed: int,
) -> bool {
    before.len() == after.len()
        && 0 <= completed <= before.len()
        && forall|i: int| 0 <= i < before.len() ==>
            if i < completed {
                after[i]@ == permute(before[i]@)
            } else {
                after[i]@ == before[i]@
            }
}

pub open spec fn rows_are_permuted(before: Seq<[u64; 16]>, after: Seq<[u64; 16]>) -> bool {
    before.len() == after.len()
        && forall|i: int| 0 <= i < before.len() ==> after[i]@ == permute(before[i]@)
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
