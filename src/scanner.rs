use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub claude_dir: PathBuf,
    pub proc_dir: PathBuf,
}

impl ScanConfig {
    pub fn host() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        Self {
            claude_dir: std::env::var_os("CLAUDE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".claude")),
            proc_dir: std::env::var_os("HOST_PROC")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/proc")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservedRoute {
    Anthropic,
    Codex,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScannedSession {
    pub name: String,
    pub session_id: Option<String>,
    /// OS pid of the backing process, present only while the session is live.
    pub pid: Option<u64>,
    /// True when a live process backs this session; false for terminated jobs
    /// enumerated from disk (done/stopped) that no longer have a process.
    pub live: bool,
    pub project: String,
    pub cwd: Option<String>,
    pub kind: String,
    /// Canonical rollup: busy|blocked|idle|stopped|done|ended|unknown.
    pub status: String,
    /// Raw job lifecycle state, when a job record exists (busy/blocked/idle/done/stopped).
    pub state: Option<String>,
    /// Human-readable status line from the job record.
    pub detail: Option<String>,
    /// What a blocked job is waiting on (job `needs`).
    pub needs: Option<String>,
    /// Final result headline from a completed job (`output.result`).
    pub result: Option<String>,
    /// Token spend recorded on the job, when available.
    pub tokens: Option<u64>,
    /// True when the session routes inference through the gateway (a non-Anthropic
    /// base URL). Determined from the effective `ANTHROPIC_BASE_URL`, not from the
    /// `CCP_ALIAS_PROVIDER` marker, which can linger stale after a mode switch.
    pub managed: bool,
    /// True when the session *can* use Remote Control — i.e. it runs native
    /// (first-party, direct to api.anthropic.com). A gateway-routed session never
    /// can, regardless of flags, so this is false for it.
    pub rc_capable: bool,
    /// True when the session is actually Remote-Control armed: it carries the
    /// `--remote-control` flag (or `remoteControlAtStartup`) AND is `rc_capable`.
    pub rc: bool,
    /// The Remote Control session name, when `--remote-control <name>` supplied one.
    pub rc_name: Option<String>,
    /// The session this one was resumed from (its `resumeSessionId` / resume-mode
    /// parent), so the dashboard can stitch a forked lineage into one session.
    pub resume_of: Option<String>,
    pub route: ObservedRoute,
    pub source: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SessionCounts {
    pub total: usize,
    pub live: usize,
    pub busy: usize,
    pub blocked: usize,
    pub codex: usize,
    pub anthropic: usize,
    pub unknown: usize,
}

/// One session's evidence gathered across the three discovery sources, keyed by
/// job short-id (== roster worker key == a live session record's `jobId`), or by
/// bare sessionId/pid for jobless interactive sessions.
#[derive(Default)]
struct Merged {
    job: Option<Value>,
    worker: Option<Value>,
    record: Option<Value>,
    pid: Option<u64>,
    environment: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanResult {
    pub scanned_at_ms: u64,
    pub counts: SessionCounts,
    pub sessions: Vec<ScannedSession>,
    pub warnings: Vec<String>,
}

pub fn scan_sessions(config: &ScanConfig) -> ScanResult {
    let mut warnings = Vec::new();
    let roster =
        read_json(&config.claude_dir.join("daemon/roster.json"), &mut warnings).unwrap_or_default();

    // Merge three discovery sources by job short-id so a session shows once no
    // matter how many places record it: the on-disk job (survives process exit),
    // the roster worker, and the live pid-keyed session file. The prior impl keyed
    // solely off live session files and demoted jobs to a name-join, so paused and
    // terminated jobs — and bg sessions whose session file lagged — vanished.
    let mut merged: BTreeMap<String, Merged> = BTreeMap::new();

    // 1. Every job on disk, including terminated ones (done/stopped) that no
    //    longer have a live process. This is the authoritative lifecycle source.
    let jobs_dir = config.claude_dir.join("jobs");
    for short in list_dirs(&jobs_dir, &mut warnings) {
        let Some(state) = read_json(&jobs_dir.join(&short).join("state.json"), &mut warnings)
        else {
            continue;
        };
        let entry = merged.entry(short.clone()).or_default();
        entry.job = Some(state);
        entry.worker = roster
            .pointer(&format!("/workers/{}", escape_pointer(&short)))
            .cloned();
    }

    // 2. Roster workers with no job dir yet (fresh dispatches, pool spares).
    if let Some(workers) = roster.get("workers").and_then(Value::as_object) {
        for (short, worker) in workers {
            let entry = merged.entry(short.clone()).or_default();
            if entry.worker.is_none() {
                entry.worker = Some(worker.clone());
            }
        }
    }

    // 3. Live pid-keyed session files whose process is actually alive. These pin
    //    the running pid and carry the process environment used for route sniffing.
    let sessions_dir = config.claude_dir.join("sessions");
    for file in list_json(&sessions_dir, &mut warnings) {
        let Some(record) = read_json(&file, &mut warnings) else {
            continue;
        };
        let Some(pid) = record.get("pid").and_then(Value::as_u64) else {
            continue;
        };
        let proc_path = config.proc_dir.join(pid.to_string());
        if !proc_path.exists() {
            continue;
        }
        let key = string_at(&record, &["jobId"])
            .or_else(|| string_at(&record, &["sessionId"]))
            .unwrap_or_else(|| format!("pid:{pid}"));
        let environment = read_environment(&proc_path.join("environ"));
        let entry = merged.entry(key).or_default();
        entry.pid = Some(pid);
        entry.environment = environment;
        entry.record = Some(record);
    }

    let mut sessions = Vec::new();
    for merged in merged.into_values() {
        let live = merged.pid.is_some();
        let job = merged.job.as_ref();
        let worker = merged.worker.as_ref();
        let record = merged.record.clone().unwrap_or(Value::Null);

        let session_id = string_at(&record, &["sessionId"])
            .or_else(|| string_at_opt(job, &["sessionId"]))
            .or_else(|| string_at_opt(worker, &["sessionId"]));

        // Skip only *unclaimed* pre-warmed spares: a spare worker with no bound
        // session identity and no job/live backing is just pool capacity. A spare
        // claimed to back a real bg session keeps source=="spare" but gains a
        // sessionId (or a job/live process), so it is kept.
        let is_spare = string_at_opt(worker, &["dispatch", "source"]).as_deref() == Some("spare");
        if is_spare && session_id.is_none() && job.is_none() {
            continue;
        }
        // Nothing durable to show: no job on disk and no live process. (A stale
        // session file for a dead pid, or a worker slot with no job, lands here.)
        if job.is_none() && !live {
            continue;
        }

        let arrays = flag_arrays(worker, job);
        // Mode hinges on the effective inference base URL, the same thing Claude
        // Code's own RC gate checks — a non-Anthropic base URL means gateway mode
        // (no RC possible); unset or api.anthropic.com means native (RC possible).
        let base_url = effective_base_url(merged.environment.as_ref(), &arrays, worker, job);
        let managed = base_url.as_deref().is_some_and(is_gateway_base_url);
        let has_metadata = merged.environment.is_some() || job.is_some() || worker.is_some();
        let evidence = mode_evidence(base_url.as_deref(), managed);
        let route = if managed {
            ObservedRoute::Unknown
        } else if has_metadata {
            ObservedRoute::Anthropic
        } else {
            ObservedRoute::Unknown
        };

        let name = string_at_opt(job, &["name"])
            .or_else(|| string_at(&record, &["name"]))
            .or_else(|| string_at_opt(worker, &["dispatch", "seed", "name"]))
            // Unnamed sessions (e.g. `claude --bg "<task>"` with no name) fall back
            // to the job's intent — the task prompt — so they stay identifiable
            // instead of collapsing to an indistinguishable "(unnamed)".
            .or_else(|| string_at_opt(job, &["intent"]).and_then(|intent| summarize(&intent)))
            .unwrap_or_else(|| "(unnamed)".to_owned());
        let cwd = string_at(&record, &["cwd"])
            .or_else(|| string_at_opt(job, &["cwd"]))
            .or_else(|| string_at_opt(worker, &["cwd"]));
        let kind = string_at(&record, &["kind"])
            .or_else(|| string_at_opt(job, &["template"]).map(normalize_kind))
            .unwrap_or_else(|| "unknown".to_owned());

        let state = string_at_opt(job, &["state"]);
        let tempo = string_at_opt(job, &["tempo"]);
        let detail = string_at_opt(job, &["detail"]);
        let needs = string_at_opt(job, &["needs"]);
        let result = string_at_opt(job, &["output", "result"]);
        let tokens = job
            .and_then(|job| job.get("tokens"))
            .and_then(Value::as_u64);
        let status = canonical_status(
            live,
            tempo.as_deref(),
            state.as_deref(),
            string_at(&record, &["status"]).as_deref(),
        );
        // Remote Control requires native mode. A gateway-routed session that
        // carries the flag can never actually bridge, so report it honestly.
        let rc_capable = !managed;
        let (rc_flag, rc_name) = remote_control_flags(&arrays, worker);
        let rc = rc_flag && rc_capable;
        let resume_of = string_at_opt(job, &["resumeSessionId"])
            .or_else(|| string_at_opt(worker, &["dispatch", "launch", "sessionId"]))
            .filter(|parent| Some(parent.as_str()) != session_id.as_deref());

        let source = string_at_opt(worker, &["dispatch", "source"])
            .or_else(|| string_at_opt(job, &["template"]).map(normalize_kind))
            .unwrap_or_else(|| {
                if kind == "interactive" {
                    "cli".to_owned()
                } else {
                    "unknown".to_owned()
                }
            });
        sessions.push(ScannedSession {
            name,
            session_id,
            pid: merged.pid,
            live,
            project: project_name(cwd.as_deref()),
            cwd,
            kind,
            status,
            state,
            detail,
            needs,
            result,
            tokens,
            managed,
            rc_capable,
            rc,
            rc_name,
            resume_of,
            route,
            source,
            evidence,
        });
    }

    sessions.sort_by(|a, b| {
        status_rank(&a.status)
            .cmp(&status_rank(&b.status))
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.session_id.cmp(&b.session_id))
    });
    let mut counts = SessionCounts {
        total: sessions.len(),
        ..SessionCounts::default()
    };
    for session in &sessions {
        if session.live {
            counts.live += 1;
        }
        match session.route {
            ObservedRoute::Codex => counts.codex += 1,
            ObservedRoute::Anthropic => counts.anthropic += 1,
            ObservedRoute::Unknown => counts.unknown += 1,
        }
        match session.status.as_str() {
            "busy" => counts.busy += 1,
            "blocked" => counts.blocked += 1,
            _ => {}
        }
    }
    ScanResult {
        scanned_at_ms: now_ms(),
        counts,
        sessions,
        warnings,
    }
}

/// Rollup a job's raw lifecycle signals into one canonical status. Live sessions
/// prefer their momentary `tempo`, then job `state`, then the session file status;
/// terminated jobs report their final `state`.
fn canonical_status(
    live: bool,
    tempo: Option<&str>,
    state: Option<&str>,
    record_status: Option<&str>,
) -> String {
    let raw = if live {
        tempo.or(state).or(record_status).unwrap_or("idle")
    } else {
        state.unwrap_or("ended")
    };
    match raw {
        "busy" | "running" | "active" => "busy",
        "blocked" | "waiting" | "needs_input" | "paused" => "blocked",
        "idle" | "ready" => "idle",
        "stopped" | "cancelled" | "canceled" | "killed" => "stopped",
        "done" | "completed" | "complete" | "finished" | "succeeded" => "done",
        "ended" | "dead" | "exited" => "ended",
        _ if live => "idle",
        _ => "ended",
    }
    .to_owned()
}

/// Sort order for the dashboard: things needing attention first, then quiet,
/// then terminated.
fn status_rank(status: &str) -> u8 {
    match status {
        "busy" => 0,
        "blocked" => 1,
        "idle" => 2,
        "stopped" => 3,
        "done" => 4,
        "ended" => 5,
        _ => 6,
    }
}

/// Normalize a job `template` value into the same vocabulary as session `kind`.
fn normalize_kind(template: String) -> String {
    match template.as_str() {
        "claude" => "interactive".to_owned(),
        _ => template,
    }
}

/// Everything needed to resume/relaunch a session with `claude`: the id to
/// resume from, its working directory, and the flags it was dispatched with.
#[derive(Debug, Clone, Serialize)]
pub struct LaunchSpec {
    /// Session id to pass to `--resume` (a terminated job resumes from its
    /// `resumeSessionId` when present, otherwise its own id).
    pub resume_id: String,
    pub cwd: Option<String>,
    /// Flags the session was dispatched with (settings, agent, permission mode).
    pub respawn_flags: Vec<String>,
    pub name: Option<String>,
    /// Existing Remote Control name, if the session already carried one.
    pub rc_name: Option<String>,
    pub live: bool,
}

/// Resolve how to relaunch a session by its full session id, searching the live
/// roster first (for running sessions whose rc dropped) then on-disk jobs (for
/// terminated sessions to relaunch). Returns None if the id is unknown.
pub fn launch_spec(config: &ScanConfig, session_id: &str) -> Option<LaunchSpec> {
    let mut warnings = Vec::new();
    let roster =
        read_json(&config.claude_dir.join("daemon/roster.json"), &mut warnings).unwrap_or_default();

    if let Some(workers) = roster.get("workers").and_then(Value::as_object) {
        for worker in workers.values() {
            let matches = string_at(worker, &["sessionId"]).as_deref() == Some(session_id)
                || string_at_opt(Some(worker), &["dispatch", "sessionId"]).as_deref()
                    == Some(session_id);
            if !matches {
                continue;
            }
            let live = worker
                .get("pid")
                .and_then(Value::as_u64)
                .is_some_and(|pid| config.proc_dir.join(pid.to_string()).exists());
            let (_, rc_name) = remote_control_flags(&flag_arrays(Some(worker), None), Some(worker));
            let respawn_flags = {
                let flags = string_array(worker.pointer("/dispatch/respawnFlags"));
                if flags.is_empty() {
                    // Resume-mode workers record their flags in launch.flagArgs.
                    string_array(worker.pointer("/dispatch/launch/flagArgs"))
                } else {
                    flags
                }
            };
            return Some(LaunchSpec {
                resume_id: session_id.to_owned(),
                cwd: string_at_opt(Some(worker), &["dispatch", "cwd"])
                    .or_else(|| string_at_opt(Some(worker), &["cwd"])),
                respawn_flags,
                name: string_at_opt(Some(worker), &["dispatch", "seed", "name"]),
                rc_name,
                live,
            });
        }
    }

    let jobs_dir = config.claude_dir.join("jobs");
    for short in list_dirs(&jobs_dir, &mut warnings) {
        let Some(job) = read_json(&jobs_dir.join(&short).join("state.json"), &mut warnings) else {
            continue;
        };
        if string_at(&job, &["sessionId"]).as_deref() != Some(session_id) {
            continue;
        }
        let (_, rc_name) = remote_control_flags(&flag_arrays(None, Some(&job)), None);
        return Some(LaunchSpec {
            resume_id: string_at(&job, &["resumeSessionId"]).unwrap_or_else(|| session_id.to_owned()),
            cwd: string_at(&job, &["cwd"]),
            respawn_flags: string_array(job.get("respawnFlags")),
            name: string_at(&job, &["name"]),
            rc_name,
            live: false,
        });
    }
    None
}

/// Reduce a free-text intent/prompt to a short one-line label (first line,
/// trimmed, ellipsized). Returns None when there's nothing usable.
fn summarize(text: &str) -> Option<String> {
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return None;
    }
    let truncated: String = line.chars().take(48).collect();
    Some(if line.chars().count() > 48 {
        format!("{}…", truncated.trim_end())
    } else {
        truncated
    })
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn read_json(path: &Path, warnings: &mut Vec<String>) -> Option<Value> {
    match fs::read(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(value) => Some(value),
            Err(error) => {
                warnings.push(format!("{}: {error}", path.display()));
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            warnings.push(format!("{}: {error}", path.display()));
            None
        }
    }
}

fn list_json(dir: &Path, warnings: &mut Vec<String>) -> Vec<PathBuf> {
    match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            warnings.push(format!("{}: {error}", dir.display()));
            Vec::new()
        }
    }
}

fn list_dirs(dir: &Path, warnings: &mut Vec<String>) -> Vec<String> {
    match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            warnings.push(format!("{}: {error}", dir.display()));
            Vec::new()
        }
    }
}

fn read_environment(path: &Path) -> Option<BTreeMap<String, String>> {
    let bytes = fs::read(path).ok()?;
    Some(
        bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .filter_map(|part| {
                let separator = part.iter().position(|byte| *byte == b'=')?;
                Some((
                    String::from_utf8_lossy(&part[..separator]).into_owned(),
                    String::from_utf8_lossy(&part[separator + 1..]).into_owned(),
                ))
            })
            .collect(),
    )
}

/// Every recorded launch/respawn flag array for a session, across the spellings
/// `claude` uses: `dispatch.launch.args` (spawn mode), `dispatch.launch.flagArgs`
/// (resume mode — previously missed), `dispatch.respawnFlags`, and the job's
/// `respawnFlags`.
fn flag_arrays<'a>(worker: Option<&'a Value>, job: Option<&'a Value>) -> Vec<&'a Vec<Value>> {
    [
        worker.and_then(|value| value.pointer("/dispatch/launch/args")),
        worker.and_then(|value| value.pointer("/dispatch/launch/flagArgs")),
        worker.and_then(|value| value.pointer("/dispatch/respawnFlags")),
        job.and_then(|value| value.get("respawnFlags")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_array)
    .collect()
}

/// The value following `flag` in any recorded flag array (e.g. the path after
/// `--settings`), ignoring a following token that is itself a flag.
fn flag_value(arrays: &[&Vec<Value>], flag: &str) -> Option<String> {
    for array in arrays {
        if let Some(index) = array.iter().position(|item| item.as_str() == Some(flag)) {
            if let Some(value) = array.get(index + 1).and_then(Value::as_str) {
                if !value.starts_with("--") {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

/// The inference base URL a session effectively uses, checked (in order) in its
/// process env, its `--settings` file's `env` block, and recorded dispatch/
/// provider env. This — not `CCP_ALIAS_PROVIDER`, which lingers stale across a
/// mode switch — is what decides gateway vs native mode.
fn effective_base_url(
    environment: Option<&BTreeMap<String, String>>,
    arrays: &[&Vec<Value>],
    worker: Option<&Value>,
    job: Option<&Value>,
) -> Option<String> {
    if let Some(url) = environment.and_then(|env| env.get("ANTHROPIC_BASE_URL")) {
        return Some(url.clone());
    }
    if let Some(path) = flag_value(arrays, "--settings") {
        if let Some(url) = settings_base_url(&path) {
            return Some(url);
        }
    }
    for env in [
        worker.and_then(|value| value.pointer("/dispatch/env")),
        job.and_then(|value| value.get("providerEnv")),
    ] {
        if let Some(url) = env
            .and_then(|env| env.get("ANTHROPIC_BASE_URL"))
            .and_then(Value::as_str)
        {
            return Some(url.to_owned());
        }
    }
    None
}

fn settings_base_url(path: &str) -> Option<String> {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("env")
                .and_then(|env| env.get("ANTHROPIC_BASE_URL"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

/// A base URL routes through the gateway when it is set to anything that is not
/// Anthropic's first-party endpoint — matching Claude Code's own RC gate, which
/// refuses Remote Control unless inference is direct to api.anthropic.com.
fn is_gateway_base_url(url: &str) -> bool {
    !url.trim().is_empty() && !url.contains("api.anthropic.com")
}

fn mode_evidence(base_url: Option<&str>, managed: bool) -> Vec<String> {
    match (managed, base_url) {
        (true, Some(url)) => vec![format!("gateway base URL: {url}")],
        (false, Some(url)) => vec![format!("native base URL: {url}")],
        (false, None) => vec!["native: no proxy base URL".to_owned()],
        (true, None) => vec!["gateway".to_owned()],
    }
}

/// Whether a session is armed for Remote Control per its launch metadata: the
/// `--remote-control [name]` flag, or a `--settings` file with
/// `remoteControlAtStartup: true`. This reports *intent*; callers gate it on
/// native mode (rc_capable) to get actual steerability.
fn remote_control_flags(arrays: &[&Vec<Value>], worker: Option<&Value>) -> (bool, Option<String>) {
    for array in arrays {
        if let Some(index) = array
            .iter()
            .position(|item| item.as_str() == Some("--remote-control"))
        {
            // `--remote-control [name]`: the name is optional and, when present,
            // is the next token that isn't itself a flag.
            let name = array
                .get(index + 1)
                .and_then(Value::as_str)
                .filter(|token| !token.starts_with("--"))
                .map(str::to_owned);
            return (true, name);
        }
    }
    // Default-on path: no explicit flag, but the session's `--settings <file>`
    // may set `remoteControlAtStartup: true`, which arms rc for every session
    // using that file. Read the referenced settings to catch that case — but
    // only trust it for sessions that launched *after* the setting was written,
    // since rc is decided at launch, not at scan time.
    let started_at = worker
        .and_then(|worker| worker.get("startedAt"))
        .and_then(Value::as_u64);
    if let Some(path) = flag_value(arrays, "--settings") {
        if settings_arms_remote_control(&path, started_at) {
            return (true, None);
        }
    }
    (false, None)
}

/// True when a `--settings` file sets `remoteControlAtStartup: true` *and* the
/// setting predates the session's launch. Without a launch time we cannot
/// confirm the session actually started with rc, so we conservatively say no —
/// a false "rc off" merely prompts a harmless re-arm, whereas a false "rc on"
/// would hide a session that silently dropped Remote Control.
fn settings_arms_remote_control(path: &str, started_at_ms: Option<u64>) -> bool {
    let armed = fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.get("remoteControlAtStartup").and_then(Value::as_bool))
        .unwrap_or(false);
    if !armed {
        return false;
    }
    match (started_at_ms, file_mtime_ms(path)) {
        (Some(started), Some(mtime)) => mtime <= started,
        _ => false,
    }
}

fn file_mtime_ms(path: &str) -> Option<u64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_millis() as u64)
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    string_at_opt(Some(value), path)
}
fn string_at_opt(mut value: Option<&Value>, path: &[&str]) -> Option<String> {
    for key in path {
        value = value?.get(*key);
    }
    value?.as_str().map(str::to_owned)
}
fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
fn project_name(cwd: Option<&str>) -> String {
    let Some(cwd) = cwd else {
        return "(unknown)".to_owned();
    };
    if cwd == "/" {
        return "/".to_owned();
    }
    Path::new(cwd)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(cwd)
        .to_owned()
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_json(path: &Path, value: Value) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
    fn live(proc_dir: &Path, pid: u64, environment: &[(&str, &str)]) {
        let dir = proc_dir.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        let bytes = environment
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join("\0");
        fs::write(dir.join("environ"), bytes).unwrap();
    }
    fn fixture() -> (TempDir, ScanConfig) {
        let temp = TempDir::new().unwrap();
        let config = ScanConfig {
            claude_dir: temp.path().join(".claude"),
            proc_dir: temp.path().join("proc"),
        };
        fs::create_dir_all(config.claude_dir.join("sessions")).unwrap();
        fs::create_dir_all(&config.proc_dir).unwrap();
        (temp, config)
    }

    #[test]
    fn joins_names_classifies_routes_and_redacts_environment() {
        let (_temp, config) = fixture();
        write_json(
            &config.claude_dir.join("sessions/101.json"),
            serde_json::json!({"pid":101,"sessionId":"interactive-id","cwd":"/home/me/project-a","kind":"interactive","name":"shell-name","status":"busy"}),
        );
        // A gateway-routed session: its inference base URL points at the local
        // proxy (not api.anthropic.com), which is what marks it managed — not the
        // CCP_ALIAS_PROVIDER marker, which can linger stale after a mode switch.
        live(
            &config.proc_dir,
            101,
            &[
                ("ANTHROPIC_BASE_URL", "http://127.0.0.1:18765"),
                ("ANTHROPIC_AUTH_TOKEN", "secret"),
            ],
        );
        write_json(
            &config.claude_dir.join("sessions/303.json"),
            serde_json::json!({"pid":303,"sessionId":"anthropic-id","cwd":"/home/me/project-c","kind":"interactive","name":"direct","status":"idle"}),
        );
        live(&config.proc_dir, 303, &[("HOME", "/home/me")]);
        let result = scan_sessions(&config);
        assert_eq!(
            result
                .sessions
                .iter()
                .map(|session| (&session.name, session.managed, &session.route))
                .collect::<Vec<_>>(),
            vec![
                (&"shell-name".to_owned(), true, &ObservedRoute::Unknown),
                (&"direct".to_owned(), false, &ObservedRoute::Anthropic)
            ]
        );
        assert!(!serde_json::to_string(&result).unwrap().contains("secret"));
    }

    #[test]
    fn skips_stale_and_spare_workers_and_warns_on_malformed_json() {
        let (_temp, config) = fixture();
        fs::write(config.claude_dir.join("sessions/broken.json"), "{").unwrap();
        write_json(
            &config.claude_dir.join("sessions/404.json"),
            serde_json::json!({"pid":404,"name":"stale"}),
        );
        write_json(
            &config.claude_dir.join("sessions/606.json"),
            serde_json::json!({"pid":606,"jobId":"spare-job"}),
        );
        write_json(
            &config.claude_dir.join("daemon/roster.json"),
            serde_json::json!({"workers":{"spare-job":{"dispatch":{"source":"spare"}}}}),
        );
        live(&config.proc_dir, 606, &[]);
        let result = scan_sessions(&config);
        assert!(result.sessions.is_empty());
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn includes_claimed_spare_backed_bg_sessions() {
        // A spare worker that has been claimed to back a real bg session keeps
        // dispatch.source == "spare" but gains a bound sessionId; it must be shown.
        let (_temp, config) = fixture();
        write_json(
            &config.claude_dir.join("sessions/707.json"),
            serde_json::json!({
                "pid":707,"sessionId":"claimed","name":"nutrition-correct-meals",
                "cwd":"/home/x/src","kind":"bg","jobId":"claimed-job"
            }),
        );
        write_json(
            &config.claude_dir.join("daemon/roster.json"),
            serde_json::json!({"workers":{"claimed-job":{"dispatch":{"source":"spare"}}}}),
        );
        live(&config.proc_dir, 707, &[]);
        let result = scan_sessions(&config);
        assert_eq!(result.sessions.len(), 1);
        assert_eq!(result.sessions[0].name, "nutrition-correct-meals");
        assert_eq!(result.sessions[0].kind, "bg");
    }

    #[test]
    fn includes_terminated_jobs_from_disk() {
        // A finished bg job leaves no live process but keeps its state.json; the
        // dashboard must still list it with its final result and token spend.
        let (_temp, config) = fixture();
        write_json(
            &config.claude_dir.join("jobs/deadbeef/state.json"),
            serde_json::json!({
                "name":"habit-tracker","state":"done","sessionId":"done-sess",
                "cwd":"/home/x/habit","template":"bg","tokens":1234,
                "output":{"result":"shipped the fix"}
            }),
        );
        let result = scan_sessions(&config);
        assert_eq!(result.sessions.len(), 1);
        let session = &result.sessions[0];
        assert_eq!(session.name, "habit-tracker");
        assert_eq!(session.status, "done");
        assert!(!session.live);
        assert_eq!(session.pid, None);
        assert_eq!(session.kind, "bg");
        assert_eq!(session.result.as_deref(), Some("shipped the fix"));
        assert_eq!(session.tokens, Some(1234));
        assert_eq!(result.counts.live, 0);
    }

    #[test]
    fn surfaces_blocked_needs_and_merges_job_with_live_session() {
        // A live bg job blocked on user input: the job carries the lifecycle and
        // the pid-keyed session file carries the process; they merge on jobId into
        // a single blocked session that reports what it needs.
        let (_temp, config) = fixture();
        write_json(
            &config.claude_dir.join("jobs/abc123/state.json"),
            serde_json::json!({
                "name":"nutrition-correct-meals","state":"blocked","tempo":"blocked",
                "needs":"confirm volume drunk","sessionId":"s1","cwd":"/home/x/nut","template":"bg"
            }),
        );
        write_json(
            &config.claude_dir.join("sessions/808.json"),
            serde_json::json!({
                "pid":808,"sessionId":"s1","jobId":"abc123","kind":"bg",
                "name":"nutrition-correct-meals","cwd":"/home/x/nut"
            }),
        );
        live(&config.proc_dir, 808, &[]);
        let result = scan_sessions(&config);
        assert_eq!(result.sessions.len(), 1);
        let session = &result.sessions[0];
        assert_eq!(session.status, "blocked");
        assert!(session.live);
        assert_eq!(session.pid, Some(808));
        assert_eq!(session.needs.as_deref(), Some("confirm volume drunk"));
        assert_eq!(result.counts.blocked, 1);
        assert_eq!(result.counts.live, 1);
    }

    #[test]
    fn detects_remote_control_and_name_from_launch_flags() {
        // A session launched `claude --bg --remote-control <name>` records the flag
        // in its worker launch args; the scanner must report it as rc-armed so the
        // dashboard can distinguish phone-steerable sessions from the rest.
        let (_temp, config) = fixture();
        write_json(
            &config.claude_dir.join("sessions/909.json"),
            serde_json::json!({"pid":909,"sessionId":"rc-sess","jobId":"rc-job","kind":"bg","name":"habit-tracker","cwd":"/home/x/h"}),
        );
        write_json(
            &config.claude_dir.join("daemon/roster.json"),
            serde_json::json!({"workers":{"rc-job":{"dispatch":{"launch":{"args":["--session-id","rc-sess","--remote-control","habit-rc","--allow-dangerously-skip-permissions"]}}}}}),
        );
        live(&config.proc_dir, 909, &[]);
        // A second session without the flag stays rc=false.
        write_json(
            &config.claude_dir.join("sessions/910.json"),
            serde_json::json!({"pid":910,"sessionId":"plain","kind":"bg","name":"plain","cwd":"/home/x/p"}),
        );
        live(&config.proc_dir, 910, &[]);
        let result = scan_sessions(&config);
        let rc = result.sessions.iter().find(|s| s.name == "habit-tracker").unwrap();
        assert!(rc.rc);
        assert_eq!(rc.rc_name.as_deref(), Some("habit-rc"));
        let plain = result.sessions.iter().find(|s| s.name == "plain").unwrap();
        assert!(!plain.rc);
        assert_eq!(plain.rc_name, None);
    }

    #[test]
    fn unnamed_session_falls_back_to_intent_summary() {
        let (_temp, config) = fixture();
        write_json(
            &config.claude_dir.join("jobs/nameless/state.json"),
            serde_json::json!({
                "state":"done","sessionId":"n1","cwd":"/home/x/n","template":"bg",
                "intent":"Migrate the nutrition catalog to versioned macros\nand backfill"
            }),
        );
        let result = scan_sessions(&config);
        assert_eq!(
            result.sessions[0].name,
            "Migrate the nutrition catalog to versioned macro…"
        );
        assert_eq!(summarize(""), None);
        assert_eq!(summarize("   "), None);
        assert_eq!(summarize("  hello  \nsecond line"), Some("hello".to_owned()));
    }

    #[test]
    fn stale_codex_env_without_base_url_is_native_and_rc_capable() {
        // The bug from the portability test: a session resumed into native mode
        // keeps a stale CCP_ALIAS_PROVIDER=codex env var but has no proxy base URL.
        // It must read as native (managed=false) and RC-capable, not gateway.
        let (_temp, config) = fixture();
        write_json(
            &config.claude_dir.join("sessions/121.json"),
            serde_json::json!({"pid":121,"sessionId":"native-id","cwd":"/home/x/n","kind":"bg","name":"resumed-native"}),
        );
        live(&config.proc_dir, 121, &[("CCP_ALIAS_PROVIDER", "codex")]);
        let s = &scan_sessions(&config).sessions[0];
        assert!(!s.managed, "stale CCP marker without base URL must not read as gateway");
        assert!(s.rc_capable, "native session must be RC-capable");
        assert_eq!(s.route, ObservedRoute::Anthropic);
    }

    #[test]
    fn remote_control_read_from_flagargs_and_gated_on_native() {
        // Resume-mode dispatches store flags in launch.flagArgs (not args). RC must
        // be detected there, and armed only when the session is native.
        let (_temp, config) = fixture();
        // Native resume with rc in flagArgs -> rc armed.
        write_json(
            &config.claude_dir.join("sessions/131.json"),
            serde_json::json!({"pid":131,"sessionId":"n","jobId":"nj","kind":"bg","name":"native-rc"}),
        );
        // Gateway session ALSO flagged rc -> rc must be false (can't bridge).
        let gw_settings = config.claude_dir.join("proxy-settings.json");
        write_json(&gw_settings, serde_json::json!({"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:18765"}}));
        write_json(
            &config.claude_dir.join("sessions/132.json"),
            serde_json::json!({"pid":132,"sessionId":"g","jobId":"gj","kind":"bg","name":"gateway-rc"}),
        );
        write_json(
            &config.claude_dir.join("daemon/roster.json"),
            serde_json::json!({"workers":{
                "nj":{"dispatch":{"launch":{"mode":"resume","sessionId":"parent-abc","flagArgs":["--remote-control","native-rc"]}}},
                "gj":{"dispatch":{"launch":{"flagArgs":["--remote-control","gateway-rc","--settings",gw_settings.to_str().unwrap()]}}}
            }}),
        );
        live(&config.proc_dir, 131, &[]);
        live(&config.proc_dir, 132, &[]);
        let result = scan_sessions(&config);
        let native = result.sessions.iter().find(|s| s.name == "native-rc").unwrap();
        assert!(native.rc, "rc flag in flagArgs must be detected on a native session");
        assert_eq!(native.rc_name.as_deref(), Some("native-rc"));
        assert_eq!(native.resume_of.as_deref(), Some("parent-abc"), "resume lineage recorded");
        let gateway = result.sessions.iter().find(|s| s.name == "gateway-rc").unwrap();
        assert!(gateway.managed, "proxy base URL in --settings marks it gateway");
        assert!(!gateway.rc_capable);
        assert!(!gateway.rc, "a gateway session can never be rc-armed");
    }

    #[test]
    fn detects_remote_control_from_settings_default() {
        // Default-on: a session launched `--settings <file>` where the file sets
        // remoteControlAtStartup:true is rc-armed even without an explicit flag.
        let (_temp, config) = fixture();
        let settings = config.claude_dir.join("codex-settings.json");
        write_json(&settings, serde_json::json!({"remoteControlAtStartup": true}));
        write_json(
            &config.claude_dir.join("sessions/911.json"),
            serde_json::json!({"pid":911,"sessionId":"def-rc","jobId":"def-job","kind":"bg","name":"defaulted","cwd":"/home/x/d"}),
        );
        // startedAt after the settings file mtime → the session launched with rc on.
        let started_after = now_ms() + 60_000;
        write_json(
            &config.claude_dir.join("daemon/roster.json"),
            serde_json::json!({"workers":{"def-job":{"startedAt":started_after,"dispatch":{"launch":{"args":["--settings",settings.to_str().unwrap(),"--agent","claude"]}}}}}),
        );
        live(&config.proc_dir, 911, &[]);
        let result = scan_sessions(&config);
        let session = result.sessions.iter().find(|s| s.name == "defaulted").unwrap();
        assert!(session.rc, "settings-based remoteControlAtStartup must arm rc");

        // A session that started *before* the setting was written is not armed.
        write_json(
            &config.claude_dir.join("sessions/912.json"),
            serde_json::json!({"pid":912,"sessionId":"old-rc","jobId":"old-job","kind":"bg","name":"predates","cwd":"/home/x/o"}),
        );
        write_json(
            &config.claude_dir.join("daemon/roster.json"),
            serde_json::json!({"workers":{
                "def-job":{"startedAt":started_after,"dispatch":{"launch":{"args":["--settings",settings.to_str().unwrap(),"--agent","claude"]}}},
                "old-job":{"startedAt":1u64,"dispatch":{"launch":{"args":["--settings",settings.to_str().unwrap(),"--agent","claude"]}}}
            }}),
        );
        live(&config.proc_dir, 912, &[]);
        let result = scan_sessions(&config);
        let old = result.sessions.iter().find(|s| s.name == "predates").unwrap();
        assert!(!old.rc, "a session predating the setting must not be reported rc-armed");
    }

    #[test]
    fn uses_unknown_fallback_without_environment_metadata() {
        let (_temp, config) = fixture();
        write_json(
            &config.claude_dir.join("sessions/505.json"),
            serde_json::json!({"pid":505,"sessionId":"x","cwd":"/","kind":"bg"}),
        );
        fs::create_dir_all(config.proc_dir.join("505")).unwrap();
        let result = scan_sessions(&config);
        assert_eq!(result.sessions[0].name, "(unnamed)");
        assert_eq!(result.sessions[0].route, ObservedRoute::Unknown);
        assert_eq!(result.sessions[0].project, "/");
    }
}
