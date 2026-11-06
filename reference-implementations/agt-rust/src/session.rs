use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, Write},
    sync::Mutex,
};

#[derive(Clone)]
struct Session {
    seq: u64,
    hash: String,
    labels: Vec<String>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            seq: 0,
            hash: "0".repeat(64),
            labels: vec!["public".into()],
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ChainEntry {
    session_id: String,
    seq: u64,
    prev_hash: String,
    hash: String,
    recorded_at: String,
    method: String,
    request_id: String,
    tool_name: String,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, Session>,
    recent: VecDeque<String>,
}

const MAX_SESSIONS: usize = 1024;

#[derive(Default)]
pub(crate) struct SessionStore(Mutex<Inner>);

fn ensure_session<'a>(inner: &'a mut Inner, session_id: &str) -> &'a mut Session {
    inner.recent.retain(|id| id != session_id);
    inner.recent.push_back(session_id.to_owned());

    while inner.recent.len() > MAX_SESSIONS {
        let Some(evicted) = inner.recent.pop_front() else {
            break;
        };
        inner.sessions.remove(&evicted);
        warn_evicted_session(&evicted);
    }

    inner.sessions.entry(session_id.to_owned()).or_default()
}

fn warn_evicted_session(session_id: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(
        stderr,
        "evicted session {session_id} from the session-context store: the retained-session cap was reached. \
A further step on this session starts a new chain at seq 1, which the Inspector renders as a chain break."
    );
}

impl SessionStore {
    pub(crate) fn append(
        &self,
        session_id: &str,
        method: &str,
        request_id: &str,
        tool_name: &str,
    ) -> Result<(ChainEntry, Vec<String>), String> {
        let mut inner = self.0.lock().map_err(|error| error.to_string())?;
        let state = ensure_session(&mut inner, session_id);
        let seq = state.seq + 1;
        let recorded_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let canonical = serde_json::to_vec(&(
            &state.hash,
            session_id,
            seq,
            &recorded_at,
            method,
            request_id,
            tool_name,
        ))
        .map_err(|error| error.to_string())?;
        let hash = format!("{:x}", Sha256::digest(canonical));
        let entry = ChainEntry {
            session_id: session_id.to_owned(),
            seq,
            prev_hash: std::mem::replace(&mut state.hash, hash.clone()),
            hash,
            recorded_at,
            method: method.to_owned(),
            request_id: request_id.to_owned(),
            tool_name: tool_name.to_owned(),
        };
        state.seq = seq;
        Ok((entry, state.labels.clone()))
    }

    pub(crate) fn replace_labels(&self, session_id: &str, labels: &[String]) -> Result<(), String> {
        let mut inner = self.0.lock().map_err(|error| error.to_string())?;
        ensure_session(&mut inner, session_id).labels = labels.to_vec();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionStore, MAX_SESSIONS};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    #[test]
    fn replace_labels_recreates_an_evicted_session_and_keeps_it_bounded() {
        let store = SessionStore::default();
        store
            .append("evicted", "steps/toolCallRequest", "initial", "Bash")
            .expect("initial append");

        for index in 0..1024 {
            store
                .append(
                    &format!("other-{index}"),
                    "steps/toolCallRequest",
                    &index.to_string(),
                    "Bash",
                )
                .expect("fill session store");
        }

        {
            let inner = store.0.lock().expect("session store lock");
            assert!(!inner.sessions.contains_key("evicted"));
            assert_eq!(inner.sessions.len(), MAX_SESSIONS);
            assert_eq!(inner.recent.len(), MAX_SESSIONS);
        }

        let propagated = vec!["confidential".to_owned()];
        store
            .replace_labels("evicted", &propagated)
            .expect("replace labels");

        let (entry, labels) = store
            .append("evicted", "steps/toolCallResult", "after-eviction", "Bash")
            .expect("append recreated session");

        assert_eq!(entry.seq, 1);
        assert_eq!(labels, propagated);

        let inner = store.0.lock().expect("session store lock");
        assert_eq!(inner.sessions.len(), MAX_SESSIONS);
        assert_eq!(inner.recent.len(), MAX_SESSIONS);
        assert!(inner.sessions.contains_key("evicted"));
    }

    #[test]
    fn appends_a_valid_chain_when_one_session_is_used_concurrently() {
        let store = Arc::new(SessionStore::default());
        let entries = std::thread::scope(|scope| {
            let jobs = (0..16)
                .map(|index| {
                    let store = Arc::clone(&store);
                    scope.spawn(move || {
                        store
                            .append(
                                "session",
                                "steps/toolCallRequest",
                                &index.to_string(),
                                "Bash",
                            )
                            .expect("append")
                            .0
                    })
                })
                .collect::<Vec<_>>();
            jobs.into_iter()
                .map(|job| job.join().expect("thread"))
                .collect::<Vec<_>>()
        });
        let mut entries = entries;
        entries.sort_by_key(|entry| entry.seq);
        let mut previous = "0".repeat(64);
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry.seq, index as u64 + 1);
            assert_eq!(entry.prev_hash, previous);
            let canonical = serde_json::to_vec(&(
                &entry.prev_hash,
                &entry.session_id,
                entry.seq,
                &entry.recorded_at,
                &entry.method,
                &entry.request_id,
                &entry.tool_name,
            ))
            .expect("canonical entry");
            assert_eq!(entry.hash, format!("{:x}", Sha256::digest(canonical)));
            previous.clone_from(&entry.hash);
        }
    }
}
