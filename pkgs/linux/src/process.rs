use anyhow::{Context, Result, ensure};
use seccy_core::{Caller, ProcessDetails, ProcessInfo};
use std::{
    fs::File,
    io::Read,
    os::{fd::AsRawFd, unix::net::UnixStream},
    time::{SystemTime, UNIX_EPOCH},
};

fn bounded(path: &str) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024 * 1024, "process metadata exceeds limit");
    String::from_utf8(bytes).context("process metadata is not UTF-8")
}

fn stat(pid: i32) -> Result<(String, Vec<String>)> {
    let text = bounded(&format!("/proc/{pid}/stat"))?;
    let start = text.find('(').context("invalid proc stat")?;
    let end = text.rfind(')').context("invalid proc stat")?;
    ensure!(end > start, "invalid proc name");
    let fields: Vec<_> = text[end + 1..]
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    ensure!(fields.len() > 19, "truncated proc stat");
    Ok((text[start + 1..end].into(), fields))
}

fn process(pid: i32) -> Result<ProcessInfo> {
    let started = std::time::Instant::now();
    let (name, fields) = stat(pid)?;
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))?
        .to_string_lossy()
        .into_owned();
    let status = bounded(&format!("/proc/{pid}/status"))?;
    let ids = |label: &str| -> Result<Vec<u32>> {
        let line = status
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .context("missing proc credentials")?;
        let values: Vec<u32> = line
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()?;
        ensure!(values.len() == 4, "invalid proc credentials");
        Ok(values)
    };
    let uid = ids("Uid:")?;
    let gid = ids("Gid:")?;
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    ensure!(ticks > 0, "cannot determine process clock frequency");
    let start_ticks: u64 = fields[19].parse()?;
    let boot: u64 = bounded("/proc/stat")?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))
        .context("boot timestamp unavailable")?
        .parse()?;
    let mut details = ProcessDetails {
        source: "Linux SO_PEERCRED and bounded /proc snapshots".into(),
        observed_at_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        terminal_device: fields[4].parse::<u32>().ok().filter(|n| *n != 0),
        terminal_foreground_group: fields[5].parse::<u32>().ok(),
        ..Default::default()
    };
    match std::fs::read_link(format!("/proc/{pid}/cwd")) {
        Ok(cwd) => details.working_directory = Some(cwd.to_string_lossy().into_owned()),
        Err(error) => details.notes.push(format!("working_directory: {error}")),
    }
    match bounded(&format!("/proc/{pid}/cmdline")) {
        Ok(args) => {
            let args: Vec<String> = args
                .strip_suffix('\0')
                .unwrap_or(&args)
                .split('\0')
                .map(str::to_owned)
                .collect();
            details.command = seccy_core::process::interpret(
                &executable,
                &args,
                details.working_directory.as_deref(),
            );
            if tracing::enabled!(tracing::Level::DEBUG) {
                details.arguments = Some(args);
            }
        }
        Err(error) => details.notes.push(format!("arguments: {error}")),
    }
    details.repository_candidate = seccy_core::process::repository_candidate(
        details.command.as_ref(),
        details.working_directory.as_deref(),
    );
    let (_, after) = stat(pid)?;
    ensure!(
        fields[19] == after[19]
            && std::fs::read_link(format!("/proc/{pid}/exe"))?.to_string_lossy() == executable,
        "process changed during inspection"
    );
    details.collection_duration_ms = started.elapsed().as_millis();
    Ok(ProcessInfo {
        pid,
        parent_pid: fields[1].parse()?,
        executable: Some(executable),
        name,
        uid: uid[1],
        gid: gid[1],
        real_uid: uid[0],
        real_gid: gid[0],
        process_group: fields[2].parse()?,
        start_time_unix_seconds: boot + start_ticks / ticks as u64,
        start_time_microseconds: (start_ticks % ticks as u64) * 1_000_000 / ticks as u64,
        details,
    })
}

pub fn caller(stream: &UnixStream) -> Result<Caller> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    ensure!(
        result == 0 && length as usize == std::mem::size_of_val(&credentials),
        "cannot identify socket peer"
    );
    ensure!(
        credentials.uid == unsafe { libc::geteuid() } && credentials.pid > 0,
        "socket peer belongs to another user"
    );
    let info = process(credentials.pid).context("cannot inspect socket peer")?;
    let executable = info
        .executable
        .clone()
        .context("peer executable unavailable")?;
    let mut parent = info.parent_pid;
    let mut ancestors = Vec::new();
    while parent > 0 && parent != credentials.pid && ancestors.len() < 16 {
        if ancestors.iter().any(|p: &ProcessInfo| p.pid == parent) {
            break;
        }
        let Ok(info) = process(parent) else {
            break;
        };
        parent = info.parent_pid;
        ancestors.push(info);
    }
    Ok(Caller {
        pid: credentials.pid,
        executable,
        peer_uid: credentials.uid,
        peer_gid: credentials.gid,
        process: Some(info),
        ancestors,
    })
}
