//! Shared, conservative interpretation of observed process arguments and files.
use crate::CommandInfo;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

pub fn interpret(executable: &str, args: &[String], cwd: Option<&str>) -> Option<CommandInfo> {
    let tool = Path::new(executable).file_name()?.to_str()?;
    if !matches!(tool, "git" | "ssh" | "ssh-keygen") {
        return None;
    }
    let mut result = CommandInfo { source: "best-effort argv interpretation; executable basename is not proof of tool identity; environment and SSH config overrides are not inspected".into(), tool: tool.into(), ..Default::default() };
    let mut directory = cwd.map(PathBuf::from);
    let mut i = 1;
    while let Some(arg) = args.get(i) {
        if tool == "git" {
            if arg == "-C" {
                let path = Path::new(args.get(i + 1)?);
                directory = if path.as_os_str().is_empty() {
                    directory
                } else if path.is_absolute() {
                    Some(path.into())
                } else {
                    directory.map(|cwd| cwd.join(path))
                };
                i += 2;
                continue;
            }
            if arg == "-c" || arg == "--work-tree" || arg == "--git-dir" {
                let value = args.get(i + 1)?;
                if arg == "--git-dir" {
                    result.git_directory_argument = Some(value.clone());
                }
                if arg == "--work-tree" {
                    result.work_tree_argument = Some(value.clone());
                }
                i += 2;
                continue;
            }
            if let Some(value) = arg.strip_prefix("--git-dir=") {
                result.git_directory_argument = Some(value.into());
                i += 1;
                continue;
            }
            if let Some(value) = arg.strip_prefix("--work-tree=") {
                result.work_tree_argument = Some(value.into());
                i += 1;
                continue;
            }
            if arg.starts_with("--config-env=")
                || matches!(
                    arg.as_str(),
                    "--no-pager" | "--paginate" | "--bare" | "--no-optional-locks"
                )
            {
                i += 1;
                continue;
            }
            if !arg.starts_with('-') {
                result.subcommand = Some(arg.clone());
            }
            break;
        } else if tool == "ssh" {
            if arg == "--" {
                result.destination_argument = args.get(i + 1).cloned();
                break;
            }
            if !arg.starts_with('-') {
                result.destination_argument = Some(arg.clone());
                break;
            }
            let mut recognized = true;
            for (offset, option) in arg[1..].char_indices() {
                if "BbcDEeFIiJLlmOopPQRSWw".contains(option) {
                    let attached = &arg[1 + offset + option.len_utf8()..];
                    let value = if attached.is_empty() {
                        i += 1;
                        args.get(i)?
                    } else {
                        attached
                    };
                    if option == 'l' {
                        result.username_argument = Some(value.into());
                    }
                    if option == 'p' {
                        result.port_argument = Some(value.into());
                    }
                    break;
                } else if !"46AaCfGgKkMNnqsTtVvXxYy".contains(option) {
                    recognized = false;
                    break;
                }
            }
            if !recognized {
                break;
            }
        } else {
            if i == 1 && arg == "-Y" {
                result.subcommand = args.get(i + 1).cloned();
            }
            break;
        }
        i += 1;
    }
    result.effective_directory_candidate = directory.map(|p| p.to_string_lossy().into_owned());
    Some(result)
}

pub fn repository(directory: &Path) -> Option<String> {
    for path in directory.ancestors().take(32) {
        let marker = path.join(".git");
        if marker.is_dir() {
            return Some(path.to_string_lossy().into_owned());
        }
        if marker.is_file() {
            let file = std::fs::File::open(&marker).ok()?;
            if !file.metadata().ok()?.is_file() {
                return None;
            }
            let mut bytes = Vec::new();
            file.take(8193).read_to_end(&mut bytes).ok()?;
            if bytes.len() > 8192 {
                return None;
            }
            if std::str::from_utf8(&bytes)
                .ok()?
                .trim()
                .starts_with("gitdir: ")
            {
                return Some(path.to_string_lossy().into_owned());
            }
        }
        if path.join("HEAD").is_file()
            && path.join("objects").is_dir()
            && path.join("refs").is_dir()
        {
            return Some(format!("{} (bare repository candidate)", path.display()));
        }
    }
    None
}

pub fn repository_candidate(command: Option<&CommandInfo>, cwd: Option<&str>) -> Option<String> {
    if let Some(path) = command.and_then(|c| c.git_directory_argument.as_deref()) {
        return Some(format!("explicit --git-dir: {path}"));
    }
    if let Some(path) = command.and_then(|c| c.work_tree_argument.as_deref()) {
        return Some(format!("explicit --work-tree: {path}"));
    }
    let directory = command
        .and_then(|c| c.effective_directory_candidate.as_deref())
        .or(cwd)?;
    repository(Path::new(directory))
}
