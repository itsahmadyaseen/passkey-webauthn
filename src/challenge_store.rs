use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Entry in the challenge store: serialized ceremony state + creation time.
struct ChallengeEntry {
    data: Vec<u8>,
    created_at: Instant,
}

/// In-memory, single-use, TTL-bounded challenge store.
///
/// Stores serialized ceremony state (registration or authentication) keyed by
/// a random ceremony ID. Entries are single-use (load-and-delete) and expire
/// after the configured TTL.
///
/// This is intentionally single-instance. For horizontal scaling, replace with
/// Redis. The README documents this limitation.
pub struct ChallengeStore {
    inner: Mutex<HashMap<Uuid, ChallengeEntry>>,
    ttl: Duration,
}

impl ChallengeStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Store ceremony state under a fresh ID. Returns the ceremony ID.
    pub fn insert(&self, data: Vec<u8>) -> Uuid {
        let id = Uuid::new_v4();
        let entry = ChallengeEntry {
            data,
            created_at: Instant::now(),
        };
        let mut map = self.inner.lock().expect("challenge store lock poisoned");
        map.insert(id, entry);
        id
    }

    /// Load and delete ceremony state — single-use.
    /// Returns None if the ID is unknown or the entry has expired.
    pub fn consume(&self, id: &Uuid) -> Option<Vec<u8>> {
        let mut map = self.inner.lock().expect("challenge store lock poisoned");
        let entry = map.remove(id)?;
        if entry.created_at.elapsed() > self.ttl {
            // Expired — treat as consumed
            None
        } else {
            Some(entry.data)
        }
    }

    /// Remove all expired entries. Called periodically by a background task.
    pub fn reap_expired(&self) {
        let mut map = self.inner.lock().expect("challenge store lock poisoned");
        map.retain(|_, entry| entry.created_at.elapsed() <= self.ttl);
    }
}
