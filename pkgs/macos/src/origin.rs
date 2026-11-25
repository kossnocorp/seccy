//! Presentation-only lookup of the local origin, never an SSH destination check.
use seccy_ui::{hosting_provider, prompt::HostedRepository};
use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub fn probe(directory: &str) -> Option<HostedRepository> {
    if !Path::new(directory).is_absolute() {
        return None;
    }
    // Git handles subdirectories, linked worktrees, and bare repositories.
    // Read local config only; don't run a remote helper or contact the host.
    let mut child = Command::new("/usr/bin/git")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-C",
            directory,
            "config",
            "--local",
            "--no-includes",
            "--null",
            "--get",
            "remote.origin.url",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) => return None,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(3)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut bytes = Vec::new();
    child
        .stdout
        .take()?
        .take(4097)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    parse(std::str::from_utf8(bytes.strip_suffix(&[0])?).ok()?)
}

fn parse(url: &str) -> Option<HostedRepository> {
    let (host, path) = if let Some((scheme, rest)) = url.split_once("://") {
        let (authority, path) = rest.split_once('/')?;
        let authority = match scheme {
            "https" | "http" | "ssh" | "git" => authority.rsplit('@').next()?,
            _ => return None,
        };
        let host = match authority.split_once(':') {
            Some((host, port))
                if matches!(
                    (scheme, port),
                    ("https", "443") | ("http", "80") | ("ssh", "22" | "443") | ("git", "9418")
                ) =>
            {
                host
            }
            Some(_) => return None,
            None => authority,
        };
        (host, path)
    } else {
        let (authority, path) = url.split_once(':')?;
        if authority.contains('/') {
            return None;
        }
        (authority.rsplit('@').next()?, path)
    };
    let provider = hosting_provider(host);
    if provider == "git" {
        return None;
    }
    let path = path.trim_end_matches('/');
    let slug = path.strip_suffix(".git").unwrap_or(path);
    let mut count = 0;
    for part in slug.split('/') {
        if part.is_empty()
            || matches!(part, "." | "..")
            || !part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return None;
        }
        count += 1;
    }
    if count < 2 || (provider != "gitlab" && count != 2) {
        return None;
    }
    Some(HostedRepository {
        provider: provider.into(),
        slug: slug.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recognizes_only_supported_hosts_and_clean_repo_paths() {
        for (url, provider, slug) in [
            (
                "git@github.com:kossnocorp/seccy.git",
                "github",
                "kossnocorp/seccy",
            ),
            (
                "https://gitlab.com/group/sub/repo.git/",
                "gitlab",
                "group/sub/repo",
            ),
            (
                "ssh://git@altssh.bitbucket.org:443/team/repo",
                "bitbucket",
                "team/repo",
            ),
        ] {
            let repo = parse(url).unwrap();
            assert_eq!(
                (repo.provider.as_str(), repo.slug.as_str()),
                (provider, slug)
            );
        }
        for url in [
            "https://github.com.example.org/a/b",
            "https://github.com@evil.example/a/b",
            "git@work:a/b",
            "/tmp/github.com:a/b",
            "git@github.com:a/../b",
        ] {
            assert!(parse(url).is_none(), "{url}");
        }
    }
    #[test]
    fn probes_origin_from_nested_working_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("src");
        std::fs::create_dir(&nested).unwrap();
        assert!(probe(nested.to_str().unwrap()).is_none());
        for args in [
            &["init", "--quiet"][..],
            &[
                "remote",
                "add",
                "origin",
                "git@gitlab.com:team/group/test.git",
            ],
        ] {
            assert!(
                Command::new("/usr/bin/git")
                    .current_dir(tmp.path())
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        assert_eq!(
            probe(nested.to_str().unwrap()).unwrap().slug,
            "team/group/test"
        );
    }
}
