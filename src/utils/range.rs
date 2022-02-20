use std::ops::{Bound, Range, RangeBounds};

pub(crate) fn range_from_bounds(
    offset: usize,
    len: usize,
    range: &impl RangeBounds<usize>,
) -> Range<usize> {
    let rel_start = match range.start_bound() {
        Bound::Unbounded => 0,
        Bound::Included(start) => *start,
        Bound::Excluded(start) => start.saturating_add(1),
    };
    let rel_end = match range.end_bound() {
        Bound::Unbounded => len,
        Bound::Included(end) => *end,
        Bound::Excluded(end) => end.saturating_sub(1),
    };

    assert!(rel_start <= len, "range start out of bounds");
    assert!(rel_end <= len, "range end out of bounds");
    assert!(rel_end >= rel_start, "range end before start");

    let start = offset + rel_start;
    let end = offset + rel_end;
    Range { start, end }
}
