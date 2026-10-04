use vstd::prelude::*;
use vstd::arithmetic::div_mod::*;
use crate::specs;

verus! {
pub proof fn geometry(memory: u32, lanes: u32, quantum: u32, segment: u32)
    requires specs::valid_params(lanes, memory, 1), quantum == 4 * lanes,
        segment == memory / quantum,
    ensures segment as int * quantum as int <= memory as int,
        segment as int * 4 <= u32::MAX,
        (segment as int * quantum as int) / lanes as int == segment as int * 4,
        (segment as int * 4) / 4 == segment as int,
        segment >= 2,
{
    lemma_fundamental_div_mod(memory as int, quantum as int);
    lemma_mod_bound(memory as int, quantum as int);
    assert(segment as int * quantum as int <= memory as int) by(nonlinear_arith)
        requires memory as int == quantum as int * segment as int + memory as int % quantum as int,
            memory as int % quantum as int >= 0;
    assert(segment as int * 4 <= segment as int * quantum as int) by(nonlinear_arith)
        requires lanes >= 1, quantum == 4 * lanes, segment >= 0;
    assert((segment as int * quantum as int) / lanes as int == segment as int * 4) by(nonlinear_arith)
        requires lanes >= 1, quantum == 4 * lanes;
    assert((segment as int * 4) / 4 == segment as int);
    lemma_div_is_ordered(8 * lanes as int, memory as int, quantum as int);
    assert((8 * lanes as int) / quantum as int == 2) by(nonlinear_arith)
        requires lanes >= 1, quantum == 4 * lanes;
}

pub proof fn square_bound(rand: u64)
    requires rand <= 0xffff_ffff,
    ensures rand as int * rand as int <= 0xffff_ffff * 0xffff_ffff,
{
    assert(rand as int * rand as int <= 0xffff_ffff * 0xffff_ffff) by(nonlinear_arith)
        requires 0 <= rand <= 0xffff_ffff;
}

pub proof fn product_bound(area: u64, square: u64, high: u64)
    requires 1 <= area <= 0xffff_ffff, square <= 0xffff_ffff * 0xffff_ffff,
        high == square / 0x1_0000_0000,
    ensures high <= 0xffff_fffe,
        area as int * high as int <= 0xffff_ffff * 0xffff_ffff,
{
    lemma_div_is_ordered(square as int, (0xffff_ffff * 0xffff_ffff) as int, 0x1_0000_0000);
    assert(high <= 0xffff_fffe);
    assert(area as int * high as int <= 0xffff_ffff * 0xffff_ffff) by(nonlinear_arith)
        requires 1 <= area <= 0xffff_ffff, 0 <= high <= 0xffff_ffff;
}

pub proof fn scaled_bound(area: u64, high: u64, product: u64, scaled: u64)
    requires area > 0, high < 0x1_0000_0000,
        product as int == area as int * high as int, scaled == product / 0x1_0000_0000,
    ensures scaled < area,
{
    assert((product as int) < area as int * 0x1_0000_0000) by(nonlinear_arith)
        requires product as int == area as int * high as int, area > 0, high < 0x1_0000_0000;
    lemma_fundamental_div_mod(product as int, 0x1_0000_0000);
    lemma_mod_bound(product as int, 0x1_0000_0000);
    assert(scaled < area) by(nonlinear_arith)
        requires product as int == 0x1_0000_0000 * scaled as int + product as int % 0x1_0000_0000,
            product as int % 0x1_0000_0000 >= 0,
            (product as int) < area as int * 0x1_0000_0000;
}

pub proof fn mapped_bound(value: u64, lane: u64)
    requires lane > 0,
    ensures value % lane < lane,
{
    lemma_mod_bound(value as int, lane as int);
}

pub proof fn position_bounds(slice: u32, segment: u32, index: u32)
    requires 2 <= segment <= 0x3fff_ffff, slice < 4, index < segment,
    ensures slice * segment <= 3 * segment,
        slice > 0 ==> slice * segment >= segment,
        slice * segment + index < 4 * segment,
        (slice + 1) * segment <= 4 * segment,
        4 * segment <= u32::MAX,
{
    assert(slice * segment <= 3 * segment) by(nonlinear_arith)
        requires 0 <= slice <= 3, segment >= 2;
    assert(slice > 0 ==> slice * segment >= segment) by(nonlinear_arith)
        requires 0 <= slice <= 3, segment >= 2;
    assert(slice * segment + index < 4 * segment) by(nonlinear_arith)
        requires 0 <= slice <= 3, 0 <= index < segment, segment >= 2;
    assert((slice + 1) * segment <= 4 * segment) by(nonlinear_arith)
        requires 0 <= slice <= 3, segment >= 2;
}
}