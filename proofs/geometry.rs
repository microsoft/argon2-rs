use vstd::prelude::*;
use vstd::arithmetic::div_mod::*;
use crate::specs;

verus! {

pub proof fn geometry(memory: u32, lanes: u32, quantum: u32, segment: u32)
    requires
        specs::valid_params(lanes, memory, 1),
        quantum == 4 * lanes,
        segment == memory / quantum,
    ensures
        segment as int * quantum as int <= memory as int,
        segment as int * 4 <= u32::MAX,
        (segment as int * quantum as int) / lanes as int == segment as int * 4,
        (segment as int * 4) / 4 == segment as int,
        segment >= 2,
{
    lemma_fundamental_div_mod(memory as int, quantum as int);
    lemma_mod_bound(memory as int, quantum as int);
    assert(segment as int * quantum as int <= memory as int) by (nonlinear_arith)
        requires
            memory as int == quantum as int * segment as int + memory as int % quantum as int,
            memory as int % quantum as int >= 0,
    ;
    assert(segment as int * 4 <= segment as int * quantum as int) by (nonlinear_arith)
        requires
            lanes >= 1,
            quantum == 4 * lanes,
            segment >= 0,
    ;
    assert((segment as int * quantum as int) / lanes as int == segment as int * 4)
        by (nonlinear_arith)
        requires
            lanes >= 1,
            quantum == 4 * lanes,
    ;
    lemma_div_is_ordered(8 * lanes as int, memory as int, quantum as int);
    assert((8 * lanes as int) / quantum as int == 2) by (nonlinear_arith)
        requires
            lanes >= 1,
            quantum == 4 * lanes,
    ;
}

pub proof fn square_bound(rand: u64)
    requires
        rand <= 0xffff_ffff,
    ensures
        rand as int * rand as int <= 0xffff_ffff * 0xffff_ffff,
{
    assert(rand as int * rand as int <= 0xffff_ffff * 0xffff_ffff) by (nonlinear_arith)
        requires
            0 <= rand <= 0xffff_ffff,
    ;
}

pub proof fn product_bound(area: u64, square: u64, high: u64)
    requires
        1 <= area <= 0xffff_ffff,
        square <= 0xffff_ffff * 0xffff_ffff,
        high == square / 0x1_0000_0000,
    ensures
        high <= 0xffff_fffe,
        area as int * high as int <= 0xffff_ffff * 0xffff_ffff,
{
    lemma_div_is_ordered(square as int, (0xffff_ffff * 0xffff_ffff) as int, 0x1_0000_0000);
    assert(area as int * high as int <= 0xffff_ffff * 0xffff_ffff) by (nonlinear_arith)
        requires
            1 <= area <= 0xffff_ffff,
            0 <= high <= 0xffff_ffff,
    ;
}

pub proof fn scaled_bound(area: u64, high: u64, product: u64, scaled: u64)
    requires
        area > 0,
        high < 0x1_0000_0000,
        product as int == area as int * high as int,
        scaled == product / 0x1_0000_0000,
    ensures
        scaled < area,
{
    assert((product as int) < area as int * 0x1_0000_0000) by (nonlinear_arith)
        requires
            product as int == area as int * high as int,
            area > 0,
            high < 0x1_0000_0000,
    ;
    lemma_fundamental_div_mod(product as int, 0x1_0000_0000);
    lemma_mod_bound(product as int, 0x1_0000_0000);
    assert(scaled < area) by (nonlinear_arith)
        requires
            product as int == 0x1_0000_0000 * scaled as int + product as int % 0x1_0000_0000,
            product as int % 0x1_0000_0000 >= 0,
            (product as int) < area as int * 0x1_0000_0000,
    ;
}

pub proof fn mapped_bound(value: u64, lane: u64)
    requires
        lane > 0,
    ensures
        value % lane < lane,
{
    lemma_mod_bound(value as int, lane as int);
}

pub proof fn position_bounds(slice: u32, segment: u32, index: u32)
    requires
        2 <= segment <= 0x3fff_ffff,
        slice < 4,
        index < segment,
    ensures
        slice * segment <= 3 * segment,
        slice > 0 ==> slice * segment >= segment,
        slice * segment + index < 4 * segment,
        (slice + 1) * segment <= 4 * segment,
        4 * segment <= u32::MAX,
{
    assert(slice * segment <= 3 * segment) by (nonlinear_arith)
        requires
            0 <= slice <= 3,
            segment >= 2,
    ;
    assert(slice > 0 ==> slice * segment >= segment) by (nonlinear_arith)
        requires
            0 <= slice <= 3,
            segment >= 2,
    ;
    assert(slice * segment + index < 4 * segment) by (nonlinear_arith)
        requires
            0 <= slice <= 3,
            0 <= index < segment,
            segment >= 2,
    ;
    assert((slice + 1) * segment <= 4 * segment) by (nonlinear_arith)
        requires
            0 <= slice <= 3,
            segment >= 2,
    ;
}

pub proof fn index_alpha_relative_bounds(area: int, j1: u32)
    requires
        1 <= area <= 0xffff_ffff,
    ensures
        0 <= area - 1 - (area * ((j1 as int * j1 as int) / 0x1_0000_0000)) / 0x1_0000_0000 < area,
{
    let divisor = 0x1_0000_0000int;
    let rand = j1 as u64;
    square_bound(rand);
    let square = rand as int * rand as int;
    let high = square / divisor;
    let maximum_square = 0xffff_ffffint * 0xffff_ffffint;
    lemma_div_is_ordered(square, maximum_square, divisor);
    lemma_fundamental_div_mod(maximum_square, divisor);

    let product = area * high;
    let scaled = product / divisor;
    let product_remainder = product % divisor;
    assert(product < area * divisor) by (nonlinear_arith)
        requires
            product == area * high,
            0 < area,
            high < divisor,
    ;
    lemma_fundamental_div_mod(product, divisor);
    lemma_mod_bound(product, divisor);
    lemma_div_is_ordered(0, product, divisor);
    assert(scaled < area) by (nonlinear_arith)
        requires
            product == divisor * scaled + product_remainder,
            0 <= product_remainder < divisor,
            product < area * divisor,
            0 < area,
    ;
}

pub proof fn index_alpha_excludes_current(pass: u32, slice: u32, segment: u32, index: u32, j1: u32)
    requires
        specs::valid_position(pass, slice, segment, index),
    ensures
        specs::index_alpha(pass, slice, segment, index, j1, true) != (slice as int * segment as int
            + index as int),
{
    let area = specs::reference_area(pass, slice, segment, index, true);
    reference_area_model_bounds(pass, slice, segment, index, true);
    index_alpha_relative_bounds(area, j1);
    let relative = area - 1 - (area * ((j1 as int * j1 as int) / 0x1_0000_0000)) / 0x1_0000_0000;
    let current = slice as int * segment as int + index as int;
    let lane = 4 * segment as int;
    let start = if pass != 0 && slice != 3 {
        (slice as int + 1) * segment as int
    } else {
        0int
    };
    assert(current < lane) by (nonlinear_arith)
        requires
            current == slice as int * segment as int + index as int,
            lane == 4 * segment as int,
            slice as int <= 3,
            (index as int) < segment as int,
            segment as int >= 2,
    ;
    if pass == 0 || slice == 3 {
        lemma_fundamental_div_mod(relative, lane);
        lemma_mod_bound(relative, lane);
        let relative_quotient = relative / lane;
        let relative_remainder = relative % lane;
        lemma_div_is_ordered(0, relative, lane);
        assert(relative_quotient == 0) by (nonlinear_arith)
            requires
                relative == lane * relative_quotient + relative_remainder,
                relative_quotient >= 0,
                0 <= relative_remainder < lane,
                relative < lane,
                lane > 0,
        ;
        assert(relative_remainder == relative) by (nonlinear_arith)
            requires
                relative == lane * relative_quotient + relative_remainder,
                relative_quotient == 0,
        ;
    } else {
        assert(start - current == segment as int - index as int) by (nonlinear_arith)
            requires
                start == (slice as int + 1) * segment as int,
                current == slice as int * segment as int + index as int,
        ;
        assert(start > current) by (nonlinear_arith)
            requires
                start - current == segment as int - index as int,
                segment as int - index as int > 0,
        ;
        assert(start + relative < current + lane) by (nonlinear_arith)
            requires
                relative < area,
                area == 3 * segment as int + index as int - 1,
                start == (slice as int + 1) * segment as int,
                current == slice as int * segment as int + index as int,
                lane == 4 * segment as int,
        ;
        let quotient = (start + relative) / lane;
        let remainder = (start + relative) % lane;
        lemma_fundamental_div_mod(start + relative, lane);
        lemma_mod_bound(start + relative, lane);
        assert(remainder != current) by (nonlinear_arith)
            requires
                start + relative == lane * quotient + remainder,
                quotient >= 0,
                0 <= remainder < lane,
                start + relative > current,
                start + relative < current + lane,
                lane > 0,
        ;
    }
}

pub proof fn reference_area_model_bounds(
    pass: u32,
    slice: u32,
    segment: u32,
    index: u32,
    same_lane: bool,
)
    requires
        specs::valid_position(pass, slice, segment, index),
    ensures
        1 <= specs::reference_area(pass, slice, segment, index, same_lane) < 4 * segment as int,
{
    if pass == 0 {
        if slice == 0 {
            assert(1 <= index as int - 1 < 4 * segment as int) by (nonlinear_arith)
                requires
                    index >= 2,
                    index < segment,
                    segment >= 2,
            ;
        } else if same_lane {
            assert(1 <= slice as int * segment as int + index as int - 1 < 4 * segment as int)
                by (nonlinear_arith)
                requires
                    1 <= slice <= 3,
                    0 <= index < segment,
                    segment >= 2,
            ;
        } else {
            assert(1 <= slice as int * segment as int - if index == 0 {
                1int
            } else {
                0int
            } < 4 * segment as int) by (nonlinear_arith)
                requires
                    1 <= slice <= 3,
                    0 <= index < segment,
                    segment >= 2,
            ;
        }
    } else if same_lane {
        assert(1 <= 3 * segment as int + index as int - 1 < 4 * segment as int) by (nonlinear_arith)
            requires
                0 <= index < segment,
                segment >= 2,
        ;
    } else {
        assert(1 <= 3 * segment as int - if index == 0 {
            1int
        } else {
            0int
        } < 4 * segment as int) by (nonlinear_arith)
            requires
                0 <= index < segment,
                segment >= 2,
        ;
    }
}

} // verus!
