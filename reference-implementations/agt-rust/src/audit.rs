use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

/// A single-process audit sink. Retained segments are never overwritten or deleted.
pub(crate) struct AuditLog {
    state: Mutex<LogState>,
    _lock: File,
}

struct LogState {
    path: PathBuf,
    file: Option<File>,
    bytes: u64,
    seq: u64,
    max_bytes: u64,
    max_files: usize,
    failure: Option<String>,
}

impl AuditLog {
    pub(crate) fn open(path: PathBuf, max_bytes: u64, max_files: usize) -> Result<Self, String> {
        if max_bytes == 0 || max_files == 0 {
            return Err("audit log limits must be positive".into());
        }
        if path.is_dir() {
            return Err("audit log path is a directory".into());
        }
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let path = parent
            .canonicalize()
            .map_err(|error| error.to_string())?
            .join(path.file_name().ok_or("audit log path has no filename")?);
        let path = if path.is_file() && !path.is_symlink() {
            path.canonicalize().map_err(|error| error.to_string())?
        } else {
            path
        };
        let mut lock_name = path.as_os_str().to_owned();
        lock_name.push(".lock");
        let mut lock_options = OpenOptions::new();
        lock_options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let lock = lock_options
            .open(PathBuf::from(lock_name))
            .map_err(|error| error.to_string())?;
        lock.try_lock()
            .map_err(|error| format!("audit log is already owned or cannot be locked: {error}"))?;
        let mut file = open_file(&path, false).map_err(|error| error.to_string())?;
        let bytes = file.metadata().map_err(|error| error.to_string())?.len();
        if bytes > max_bytes {
            return Err("existing audit log exceeds its configured segment limit".into());
        }
        check_tail(&mut file, bytes).map_err(|error| error.to_string())?;
        check_retained_segments(&path, max_bytes, max_files)?;
        Ok(Self {
            state: Mutex::new(LogState {
                path,
                file: Some(file),
                bytes,
                seq: 0,
                max_bytes,
                max_files,
                failure: None,
            }),
            _lock: lock,
        })
    }

    /// Whether the sink can still accept records. It is false only after a
    /// failure that may have left a partial record or rotation behind.
    pub(crate) fn available(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.failure.is_none())
    }

    /// The largest record, without its line separator, that fits in one segment.
    pub(crate) fn max_record_bytes(&self) -> u64 {
        self.state
            .lock()
            .map_or(0, |state| state.max_bytes.saturating_sub(1))
    }

    pub(crate) fn append(
        &self,
        record: impl FnOnce(u64) -> Result<Vec<u8>, String>,
    ) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|error| error.to_string())?;
        if let Some(failure) = &state.failure {
            return Err(failure.clone());
        }
        let record = record(state.seq + 1)?;
        match state.append_record(record) {
            Ok(()) => Ok(()),
            // Nothing was written, so the sink stays usable. A full retention
            // budget clears as soon as an operator archives a segment.
            Err(Failure::Refused(error)) => Err(error),
            Err(Failure::Broken(error)) => {
                // Never resume after a partial write, failed flush or incomplete rotation.
                state.failure = Some(error.clone());
                Err(error)
            }
        }
    }
}

/// Why an append failed, and whether the sink may have been changed.
enum Failure {
    /// Refused before anything was written or moved.
    Refused(String),
    /// A write, flush, sync or rotation step failed part way.
    Broken(String),
}

fn broken(error: impl ToString) -> Failure {
    Failure::Broken(error.to_string())
}

impl LogState {
    fn append_record(&mut self, mut record: Vec<u8>) -> Result<(), Failure> {
        record.push(b'\n');
        let bytes = u64::try_from(record.len()).map_err(broken)?;
        if bytes > self.max_bytes {
            return Err(Failure::Refused(
                "audit record exceeds the log segment limit".into(),
            ));
        }
        if self.bytes > self.max_bytes - bytes {
            self.rotate()?;
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| broken("audit log is unavailable"))?;
        write_record(file, &record).map_err(broken)?;
        file.sync_data().map_err(broken)?;
        self.bytes += bytes;
        self.seq += 1;
        Ok(())
    }

    fn rotate(&mut self) -> Result<(), Failure> {
        if self.max_files == 1
            || segment(&self.path, self.max_files - 1)
                .try_exists()
                .map_err(broken)?
        {
            return Err(Failure::Refused(
                "audit retention is full; archive retained segments first".into(),
            ));
        }
        self.move_segments().map_err(broken)
    }

    fn move_segments(&mut self) -> io::Result<()> {
        let file = self
            .file
            .take()
            .ok_or_else(|| io::Error::other("audit log is unavailable"))?;
        file.sync_all()?;
        drop(file);
        for index in (1..self.max_files - 1).rev() {
            let from = segment(&self.path, index);
            if from.try_exists()? {
                move_without_overwrite(&from, &segment(&self.path, index + 1))?;
            }
        }
        move_without_overwrite(&self.path, &segment(&self.path, 1))?;
        self.file = Some(open_file(&self.path, true)?);
        self.bytes = 0;
        Ok(())
    }
}

fn segment(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn move_without_overwrite(from: &Path, to: &Path) -> io::Result<()> {
    // hard_link atomically refuses an existing destination on Unix and Windows.
    // If either operation fails, all existing records remain and the sink latches shut.
    fs::hard_link(from, to)?;
    fs::remove_file(from)
}

fn open_file(path: &Path, new: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true);
    if new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn write_record(writer: &mut impl Write, record: &[u8]) -> io::Result<()> {
    writer.write_all(record)?;
    writer.flush()
}

fn check_tail(file: &mut File, bytes: u64) -> io::Result<()> {
    if bytes != 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0];
        file.read_exact(&mut last)?;
        if last != *b"\n" {
            return Err(io::Error::other(
                "audit log has an incomplete last record; preserve and repair it before restart",
            ));
        }
    }
    Ok(())
}

fn check_retained_segments(path: &Path, max_bytes: u64, max_files: usize) -> Result<(), String> {
    let mut prefix = path
        .file_name()
        .ok_or("audit log has no filename")?
        .as_encoded_bytes()
        .to_vec();
    prefix.push(b'.');
    for entry in fs::read_dir(path.parent().ok_or("audit log has no parent")?)
        .map_err(|error| error.to_string())?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        let Some(suffix) = name.as_encoded_bytes().strip_prefix(prefix.as_slice()) else {
            continue;
        };
        if suffix.is_empty() || !suffix.iter().all(u8::is_ascii_digit) {
            continue;
        }
        let index = std::str::from_utf8(suffix)
            .unwrap()
            .parse::<usize>()
            .map_err(|_| "retained audit segment exceeds its configured file limit")?;
        if index == 0 || index >= max_files || index.to_string().as_bytes() != suffix {
            return Err("retained audit segment exceeds its configured file limit".into());
        }
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.len() > max_bytes {
            return Err(
                "retained audit segment is not a file within its configured size limit".into(),
            );
        }
        let mut file = File::open(entry.path()).map_err(|error| error.to_string())?;
        check_tail(&mut file, metadata.len()).map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{segment, write_record, AuditLog};
    use std::{
        fs, io,
        io::Write,
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    };

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "acs-audit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> PathBuf {
            self.0.join("audit.jsonl")
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn rotates_without_losing_records_and_resumes_once_a_segment_is_archived() {
        let dir = Directory::new();
        let log = AuditLog::open(dir.path(), 4, 3).unwrap();
        for record in [b"one", b"two", b"tri"] {
            log.append(|_| Ok(record.to_vec())).unwrap();
        }
        assert_eq!(fs::read(segment(&dir.path(), 2)).unwrap(), b"one\n");
        assert_eq!(fs::read(segment(&dir.path(), 1)).unwrap(), b"two\n");
        assert_eq!(fs::read(dir.path()).unwrap(), b"tri\n");
        // Full retention refuses the record without touching retained history.
        assert!(log.append(|_| Ok(b"end".to_vec())).is_err());
        assert!(log.available());
        assert_eq!(fs::read(segment(&dir.path(), 2)).unwrap(), b"one\n");
        assert_eq!(fs::read(dir.path()).unwrap(), b"tri\n");
        // An operator archives the oldest segment; the sink resumes without a restart.
        let archived = dir.0.join("archived.jsonl");
        fs::rename(segment(&dir.path(), 2), &archived).unwrap();
        log.append(|_| Ok(b"end".to_vec())).unwrap();
        assert_eq!(fs::read(&archived).unwrap(), b"one\n");
        assert_eq!(fs::read(segment(&dir.path(), 2)).unwrap(), b"two\n");
        assert_eq!(fs::read(segment(&dir.path(), 1)).unwrap(), b"tri\n");
        assert_eq!(fs::read(dir.path()).unwrap(), b"end\n");
        drop(log);
    }

    #[test]
    fn counts_existing_bytes_and_the_record_separator_in_the_limit() {
        let dir = Directory::new();
        fs::write(dir.path(), b"old\n").unwrap();
        let log = AuditLog::open(dir.path(), 4, 2).unwrap();
        log.append(|_| Ok(b"new".to_vec())).unwrap();
        assert_eq!(fs::read(segment(&dir.path(), 1)).unwrap(), b"old\n");
        assert_eq!(fs::read(dir.path()).unwrap(), b"new\n");
        drop(log);
    }

    #[test]
    fn rejects_open_errors_invalid_limits_and_records_larger_than_a_segment() {
        let dir = Directory::new();
        assert!(AuditLog::open(dir.0.clone(), 4, 2).is_err());
        assert!(AuditLog::open(dir.path(), 0, 2).is_err());
        assert!(AuditLog::open(dir.path(), 4, 0).is_err());
        let log = AuditLog::open(dir.path(), 4, 2).unwrap();
        assert!(log.append(|_| Ok(b"large".to_vec())).is_err());
        assert!(fs::read(dir.path()).unwrap().is_empty());
        // Nothing was written, so the oversized record does not close the sink.
        assert!(log.available());
        assert_eq!(log.max_record_bytes(), 3);
        log.append(|_| Ok(b"ok".to_vec())).unwrap();
        assert_eq!(fs::read(dir.path()).unwrap(), b"ok\n");
        drop(log);
    }

    #[test]
    fn rotation_errors_latch_without_removing_the_active_log() {
        let dir = Directory::new();
        let log = AuditLog::open(dir.path(), 4, 3).unwrap();
        log.append(|_| Ok(b"one".to_vec())).unwrap();
        fs::create_dir(segment(&dir.path(), 1)).unwrap();
        assert!(log.append(|_| Ok(b"two".to_vec())).is_err());
        assert_eq!(fs::read(dir.path()).unwrap(), b"one\n");
        assert!(!log.available());
        drop(log);
    }

    #[test]
    fn serializes_concurrent_writes_and_sequence_numbers() {
        let dir = Directory::new();
        let log = Arc::new(AuditLog::open(dir.path(), 16, 100).unwrap());
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let log = Arc::clone(&log);
                scope.spawn(move || {
                    for _ in 0..16 {
                        log.append(|seq| Ok(seq.to_string().into_bytes())).unwrap();
                    }
                });
            }
        });
        let mut text = String::new();
        for index in (1..100).rev() {
            let path = segment(&dir.path(), index);
            if path.exists() {
                assert!(fs::metadata(&path).unwrap().len() <= 16);
                text.push_str(&fs::read_to_string(path).unwrap());
            }
        }
        text.push_str(&fs::read_to_string(dir.path()).unwrap());
        let values: Vec<_> = text
            .lines()
            .map(|line| line.parse::<u64>().unwrap())
            .collect();
        assert_eq!(values, (1..=256).collect::<Vec<_>>());
        drop(log);
    }

    #[test]
    fn propagates_both_write_and_flush_failures() {
        struct FailingWriter(bool);
        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.0 {
                    Ok(bytes.len())
                } else {
                    Err(io::Error::other("write failed"))
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("flush failed"))
            }
        }
        for accepts_write in [false, true] {
            assert!(write_record(&mut FailingWriter(accepts_write), b"record\n").is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_write_failure_latches_the_sink_closed() {
        let dir = Directory::new();
        std::os::unix::fs::symlink("/dev/full", dir.path()).unwrap();
        let log = AuditLog::open(dir.path(), 1024, 2).unwrap();
        assert!(log.append(|_| Ok(b"one".to_vec())).is_err());
        assert!(!log.available());
        assert!(log.append(|_| Ok(b"two".to_vec())).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_sync_failure_after_a_successful_write_latches_the_sink_closed() {
        let dir = Directory::new();
        std::os::unix::fs::symlink("/dev/null", dir.path()).unwrap();
        let log = AuditLog::open(dir.path(), 1024, 2).unwrap();
        assert!(log.append(|_| Ok(b"one".to_vec())).is_err());
        assert!(!log.available());
    }

    #[test]
    fn rejects_existing_history_that_exceeds_the_configured_limit() {
        let dir = Directory::new();
        fs::write(dir.path(), b"too large\n").unwrap();
        assert!(AuditLog::open(dir.path(), 4, 2).is_err());
        fs::write(dir.path(), b"").unwrap();
        fs::write(segment(&dir.path(), 1), b"too large\n").unwrap();
        assert!(AuditLog::open(dir.path(), 4, 2).is_err());
    }

    #[test]
    fn refuses_to_append_to_an_incomplete_record_after_restart() {
        let dir = Directory::new();
        fs::write(dir.path(), b"{\"part").unwrap();
        assert!(AuditLog::open(dir.path(), 1024, 2).is_err());
        assert_eq!(fs::read(dir.path()).unwrap(), b"{\"part");
    }

    #[test]
    fn refuses_shared_paths_even_across_distinct_sink_instances() {
        let dir = Directory::new();
        let log = AuditLog::open(dir.path(), 1024, 2).unwrap();
        assert!(AuditLog::open(dir.path(), 1024, 2).is_err());
        drop(log);
        assert!(AuditLog::open(dir.path(), 1024, 2).is_ok());
    }

    #[test]
    fn lowering_retention_refuses_existing_segments_outside_the_new_budget() {
        let dir = Directory::new();
        let log = AuditLog::open(dir.path(), 4, 3).unwrap();
        for record in [b"one", b"two", b"tri"] {
            log.append(|_| Ok(record.to_vec())).unwrap();
        }
        drop(log);
        for max_files in [1, 2] {
            assert!(AuditLog::open(dir.path(), 4, max_files).is_err());
        }
        assert_eq!(fs::read(segment(&dir.path(), 2)).unwrap(), b"one\n");
        assert_eq!(fs::read(segment(&dir.path(), 1)).unwrap(), b"two\n");
        assert_eq!(fs::read(dir.path()).unwrap(), b"tri\n");
    }
}
