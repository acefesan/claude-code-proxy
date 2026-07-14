use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
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
    pub pid: u64,
    pub project: String,
    pub cwd: Option<String>,
    pub kind: String,
    pub status: String,
    pub route: ObservedRoute,
    pub source: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SessionCounts {
    pub total: usize,
    pub busy: usize,
    pub codex: usize,
    pub anthropic: usize,
    pub unknown: usize,
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
    let mut sessions = Vec::new();
    let sessions_dir = config.claude_dir.join("sessions");
    let files = list_json(&sessions_dir, &mut warnings);

    for file in files {
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

        let job_id = string_at(&record, &["jobId"]);
        let job = job_id.as_deref().and_then(|id| {
            read_json(
                &config.claude_dir.join("jobs").join(id).join("state.json"),
                &mut warnings,
            )
        });
        let worker = job_id
            .as_deref()
            .and_then(|id| roster.pointer(&format!("/workers/{}", escape_pointer(id))));
        // Skip only *unclaimed* pre-warmed spares. When a spare worker is claimed
        // to back a real session its roster `dispatch.source` stays "spare", so
        // gating on source alone drops live bg sessions launched from the spare
        // pool (e.g. `nutrition-correct-meals`). A claimed session carries a bound
        // `sessionId` in its record; an idle spare does not.
        let is_unclaimed_spare = string_at_opt(worker, &["dispatch", "source"]).as_deref()
            == Some("spare")
            && string_at(&record, &["sessionId"]).is_none();
        if is_unclaimed_spare {
            continue;
        }
        let environment = read_environment(&proc_path.join("environ"));
        let evidence = routing_evidence(environment.as_ref(), job.as_ref(), worker);
        let has_metadata = environment.is_some() || job.is_some() || worker.is_some();
        let route = if !evidence.is_empty() {
            ObservedRoute::Codex
        } else if has_metadata {
            ObservedRoute::Anthropic
        } else {
            ObservedRoute::Unknown
        };
        let name = string_at_opt(job.as_ref(), &["name"])
            .or_else(|| string_at(&record, &["name"]))
            .or_else(|| string_at_opt(worker, &["dispatch", "seed", "name"]))
            .unwrap_or_else(|| "(unnamed)".to_owned());
        let cwd = string_at(&record, &["cwd"])
            .or_else(|| string_at_opt(job.as_ref(), &["cwd"]))
            .or_else(|| string_at_opt(worker, &["cwd"]));
        let kind = string_at(&record, &["kind"]).unwrap_or_else(|| "unknown".to_owned());
        let status = string_at(&record, &["status"]).unwrap_or_else(|| "unknown".to_owned());
        let source = string_at_opt(worker, &["dispatch", "source"]).unwrap_or_else(|| {
            if kind == "interactive" {
                "cli".to_owned()
            } else {
                "unknown".to_owned()
            }
        });
        let fallback_evidence = match route {
            ObservedRoute::Anthropic => Some("no Codex routing marker"),
            ObservedRoute::Unknown => Some("insufficient metadata"),
            ObservedRoute::Codex => None,
        };
        sessions.push(ScannedSession {
            name,
            session_id: string_at(&record, &["sessionId"])
                .or_else(|| string_at_opt(job.as_ref(), &["sessionId"]))
                .or_else(|| string_at_opt(worker, &["sessionId"])),
            pid,
            project: project_name(cwd.as_deref()),
            cwd,
            kind,
            status,
            route,
            source,
            evidence: if evidence.is_empty() {
                vec![
                    fallback_evidence
                        .expect("non-Codex routes have fallback evidence")
                        .to_owned(),
                ]
            } else {
                evidence
            },
        });
    }

    sessions.sort_by(|a, b| {
        let a_busy = a.status == "busy";
        let b_busy = b.status == "busy";
        b_busy
            .cmp(&a_busy)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    let mut counts = SessionCounts {
        total: sessions.len(),
        ..SessionCounts::default()
    };
    for session in &sessions {
        match session.route {
            ObservedRoute::Codex => counts.codex += 1,
            ObservedRoute::Anthropic => counts.anthropic += 1,
            ObservedRoute::Unknown => counts.unknown += 1,
        }
        if session.status == "busy" {
            counts.busy += 1;
        }
    }
    ScanResult {
        scanned_at_ms: now_ms(),
        counts,
        sessions,
        warnings,
    }
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

fn routing_evidence(
    environment: Option<&BTreeMap<String, String>>,
    job: Option<&Value>,
    worker: Option<&Value>,
) -> Vec<String> {
    let mut evidence = BTreeSet::new();
    if environment
        .and_then(|env| env.get("CCP_ALIAS_PROVIDER"))
        .is_some_and(|value| value == "codex")
    {
        evidence.insert("process env: CCP_ALIAS_PROVIDER=codex".to_owned());
    }
    if environment
        .and_then(|env| env.get("ANTHROPIC_BASE_URL"))
        .is_some_and(|value| value.starts_with("http://127.0.0.1:18765"))
    {
        evidence.insert("process env: local Codex proxy".to_owned());
    }
    let launch = flatten(worker.and_then(|value| value.pointer("/dispatch/launch")));
    let daemon_env = flatten(worker.and_then(|value| value.pointer("/dispatch/env")));
    let job_flags = flatten(job.and_then(|value| value.get("respawnFlags")));
    let provider_env = flatten(job.and_then(|value| value.get("providerEnv")));
    if [&launch, &daemon_env, &job_flags, &provider_env]
        .iter()
        .any(|text| text.contains("claude-code-proxy-codex"))
    {
        evidence.insert("launch metadata: Codex settings".to_owned());
    }
    if [&daemon_env, &provider_env]
        .iter()
        .any(|text| text.contains("CCP_ALIAS_PROVIDER=codex"))
    {
        evidence.insert("launch metadata: Codex provider".to_owned());
    }
    evidence.into_iter().collect()
}

fn flatten(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| flatten(Some(value)))
            .collect::<Vec<_>>()
            .join(" "),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| format!("{key}={}", flatten(Some(value))))
            .collect::<Vec<_>>()
            .join(" "),
    }
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
        live(
            &config.proc_dir,
            101,
            &[
                ("CCP_ALIAS_PROVIDER", "codex"),
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
                .map(|session| (&session.name, &session.route))
                .collect::<Vec<_>>(),
            vec![
                (&"shell-name".to_owned(), &ObservedRoute::Codex),
                (&"direct".to_owned(), &ObservedRoute::Anthropic)
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
