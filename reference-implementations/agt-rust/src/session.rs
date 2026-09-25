use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
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

#[derive(Default)]
pub(crate) struct SessionStore(Mutex<Inner>);

impl SessionStore {
    pub(crate) fn append(
        &self,
        session_id: &str,
        method: &str,
        request_id: &str,
        tool_name: &str,
    ) -> Result<(ChainEntry, Vec<String>), String> {
        let mut inner = self.0.lock().map_err(|error| error.to_string())?;
        inner.recent.retain(|id| id != session_id);
        inner.recent.push_back(session_id.to_owned());
        if inner.recent.len() > 1024 {
            if let Some(evicted) = inner.recent.pop_front() {
                inner.sessions.remove(&evicted);
                eprintln!("evicted session {evicted}: retained-session cap reached");
            }
        }
        let state = inner.sessions.entry(session_id.to_owned()).or_default();
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
        if let Some(state) = inner.sessions.get_mut(session_id) {
            state.labels = labels.to_vec();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SessionStore;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

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
