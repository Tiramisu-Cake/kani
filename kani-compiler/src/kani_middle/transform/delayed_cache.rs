// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! First-write journal for the cache entries replaced by the delayed UB pass.
//! Generic keys/values let the ownership lifecycle be tested without fabricating
//! compiler Instances or MIR Bodies. Production stores exact TransformationResults.

use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug)]
pub(super) struct DelayedCache<K, V> {
    originals: Option<HashMap<K, Option<V>>>,
}

impl<K, V> Default for DelayedCache<K, V> {
    fn default() -> Self {
        Self { originals: None }
    }
}

impl<K: Copy + Eq + Hash, V> DelayedCache<K, V> {
    pub(super) fn begin(&mut self) {
        assert!(self.originals.is_none(), "previous delayed transformation scope is still active");
        self.originals = Some(HashMap::new());
    }

    pub(super) fn replace(&mut self, cache: &mut HashMap<K, V>, key: K, value: V) {
        let originals = self.originals.as_mut().expect("delayed replacement outside a model scope");
        // Move the complete original, including the modified flag, without cloning
        // MIR or replacing an earlier snapshot with an intermediate delayed body.
        let previous = cache.insert(key, value);
        originals.entry(key).or_insert(previous);
    }

    pub(super) fn restore(&mut self, cache: &mut HashMap<K, V>) {
        let originals = self.originals.take().expect("no delayed transformation scope to restore");
        for (key, original) in originals {
            match original {
                Some(value) => {
                    cache.insert(key, value);
                }
                None => {
                    cache.remove(&key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DelayedCache;
    use std::collections::HashMap;

    // Deliberately non-Clone: restoration must move the exact original value.
    #[derive(Debug, Eq, PartialEq)]
    struct Result {
        body: Vec<u8>,
        modified: bool,
    }

    fn result(body: u8, modified: bool) -> Result {
        Result { body: vec![body], modified }
    }

    #[test]
    fn first_snapshot_restores_body_and_modified_flag() {
        for modified in [false, true] {
            let mut cache = HashMap::from([(1, result(10, modified))]);
            let mut journal = DelayedCache::default();
            journal.begin();
            journal.replace(&mut cache, 1, result(20, true));
            journal.replace(&mut cache, 1, result(30, true));
            assert_eq!(cache[&1], result(30, true));
            assert_eq!(journal.originals.as_ref().unwrap().len(), 1);
            journal.restore(&mut cache);
            assert_eq!(cache[&1], result(10, modified));
            assert!(journal.originals.is_none());
        }
    }

    #[test]
    fn preserves_warm_untouched_and_new_regular_entries() {
        let mut cache = HashMap::from([(1, result(10, true)), (2, result(11, false))]);
        let mut journal = DelayedCache::default();
        journal.begin();
        journal.replace(&mut cache, 1, result(20, true));
        cache.insert(3, result(12, true));
        // A body first regular-transformed during this scope must stay regular.
        cache.insert(4, result(13, false));
        journal.replace(&mut cache, 4, result(21, true));
        journal.restore(&mut cache);
        assert_eq!(
            cache,
            HashMap::from([
                (1, result(10, true)),
                (2, result(11, false)),
                (3, result(12, true)),
                (4, result(13, false)),
            ])
        );
    }

    #[test]
    fn removes_previously_absent_failed_root_and_repeats_cleanly() {
        let mut cache = HashMap::new();
        let mut journal = DelayedCache::default();
        for _ in 0..3 {
            journal.begin();
            journal.replace(&mut cache, 1, result(99, true));
            journal.replace(&mut cache, 1, result(100, true));
            assert_eq!(cache[&1], result(100, true));
            journal.restore(&mut cache);
            assert!(cache.is_empty());
            assert!(journal.originals.is_none());
        }
    }

    #[test]
    fn empty_scope_preserves_regular_cache() {
        let mut cache = HashMap::from([(1, result(10, false))]);
        let mut journal = DelayedCache::default();
        for _ in 0..2 {
            journal.begin();
            journal.restore(&mut cache);
            assert_eq!(cache[&1], result(10, false));
        }
    }

    #[test]
    #[should_panic(expected = "previous delayed transformation scope is still active")]
    fn rejects_unclosed_scope() {
        let mut journal = DelayedCache::<u8, Result>::default();
        journal.begin();
        journal.begin();
    }

    #[test]
    #[should_panic(expected = "delayed replacement outside a model scope")]
    fn rejects_unscoped_replacement() {
        DelayedCache::default().replace(&mut HashMap::new(), 1, result(10, true));
    }
}
