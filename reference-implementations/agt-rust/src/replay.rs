//! §10.3 replay protection: duplicate `request_id` values within a session.

use std::{collections::HashMap, sync::Mutex};

const MAX_SESSIONS: usize = 4096;
const MAX_ENTRIES: usize = 65_536;

pub(crate) enum Freshness {
    Fresh,
    Replay,
    /// The store is full of records that are still valid. Evicting one would
    /// let that request be replayed, so the request is refused instead.
    Capacity,
}

/// Request ids seen per session, each kept until its timestamp could no
/// longer pass the skew window. The check and the insert happen under one
/// lock, so two concurrent copies of a request cannot both be accepted.
#[derive(Default)]
pub(crate) struct ReplayStore(Mutex<Inner>);

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, HashMap<String, i64>>,
    entries: usize,
}

impl ReplayStore {
    /// Remember `request_id` for `session_id` until `valid_until_ms`, or report
    /// that it was already seen.
    pub(crate) fn check_and_remember(
        &self,
        session_id: &str,
        request_id: &str,
        now_ms: i64,
        valid_until_ms: i64,
    ) -> Result<Freshness, String> {
        let mut inner = self
            .0
            .lock()
            .map_err(|_| "replay-protection state is unavailable")?;
        let inner = &mut *inner;
        let mut removed = 0;
        inner.sessions.retain(|_, ids| {
            let before = ids.len();
            ids.retain(|_, expires| *expires >= now_ms);
            removed += before - ids.len();
            !ids.is_empty()
        });
        inner.entries -= removed;

        if inner
            .sessions
            .get(session_id)
            .is_some_and(|ids| ids.contains_key(request_id))
        {
            return Ok(Freshness::Replay);
        }
        let new_session = !inner.sessions.contains_key(session_id);
        if inner.entries >= MAX_ENTRIES || (new_session && inner.sessions.len() >= MAX_SESSIONS) {
            return Ok(Freshness::Capacity);
        }
        inner
            .sessions
            .entry(session_id.to_owned())
            .or_default()
            .insert(request_id.to_owned(), valid_until_ms);
        inner.entries += 1;
        Ok(Freshness::Fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_repeat_in_the_same_session_until_it_expires() {
        let store = ReplayStore::default();
        let fresh = |session, id, now| {
            matches!(
                store.check_and_remember(session, id, now, 1_000).unwrap(),
                Freshness::Fresh
            )
        };
        assert!(fresh("s1", "r1", 0));
        assert!(!fresh("s1", "r1", 500));
        assert!(fresh("s2", "r1", 500));
        assert!(fresh("s1", "r1", 1_001));
    }
}
