//! Host preflight filter union; filter order does not affect receipt inclusion.
use alloy_primitives::map::HashSet;
use alloy_rpc_types::Filter;

pub(crate) fn merge_log_filters(left: Vec<Filter>, right: Vec<Filter>) -> Vec<Filter> {
    let mut seen: HashSet<_> = HashSet::default();
    left.into_iter()
        .chain(right)
        .filter(|filter| {
            // Filter equality compares sets, ignoring their iteration order and
            // lazy bloom caches. Hash a canonical representation of those sets.
            let mut addresses: Vec<_> = filter.address.iter().copied().collect();
            addresses.sort_unstable();
            let topics = filter.topics.each_ref().map(|topic| {
                let mut values: Vec<_> = topic.iter().copied().collect();
                values.sort_unstable();
                values
            });
            seen.insert((filter.block_option, addresses, topics))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};

    fn filter() -> Filter {
        Filter::new()
            .at_block_hash(B256::repeat_byte(1))
            .address(vec![Address::repeat_byte(2), Address::repeat_byte(3)])
            .event_signature(vec![B256::repeat_byte(4), B256::repeat_byte(5)])
    }

    #[test]
    fn duplicates_reordered_sets_and_cached_blooms_merge_once() {
        let first = filter();
        let reordered = Filter::new()
            .at_block_hash(B256::repeat_byte(1))
            .address(vec![Address::repeat_byte(3), Address::repeat_byte(2)])
            .event_signature(vec![B256::repeat_byte(5), B256::repeat_byte(4)]);
        let _ = reordered.address.bloom_filter();
        let _ = reordered.topics[0].bloom_filter();
        assert_eq!(first, reordered);
        let merged = merge_log_filters(vec![first.clone(), first.clone()], vec![reordered]);
        assert_eq!(merged, vec![first]);
    }

    #[test]
    fn distinct_blocks_addresses_topics_and_positions_remain_distinct() {
        let original = filter();
        let block = original.clone().at_block_hash(B256::repeat_byte(9));
        let address = original.clone().address(Address::repeat_byte(9));
        let topic = original.clone().event_signature(B256::repeat_byte(9));
        let mut position = original.clone();
        position.topics.swap(0, 1);
        let wildcard = Filter::new().at_block_hash(B256::repeat_byte(1));
        let expected = vec![original, block, address, topic, position, wildcard];
        let merged = merge_log_filters(expected[..3].to_vec(), expected[3..].to_vec());
        assert_eq!(merged.len(), expected.len());
        for value in expected {
            assert!(merged.contains(&value));
        }
    }

    #[test]
    fn empty_inputs_preserve_wildcard() {
        assert!(merge_log_filters(vec![], vec![]).is_empty());
        let wildcard = Filter::new();
        assert_eq!(
            merge_log_filters(vec![], vec![wildcard.clone()]),
            vec![wildcard.clone()]
        );
        assert_eq!(
            merge_log_filters(vec![wildcard.clone()], vec![]),
            vec![wildcard]
        );
    }
}
