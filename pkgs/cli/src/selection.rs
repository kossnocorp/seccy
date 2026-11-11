//! Small terminal picker. Uses the controlling terminal so piped secrets remain untouched.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::{IsTerminal, Read, Write},
    os::fd::{AsRawFd, RawFd},
};

struct Terminal {
    file: File,
    original: libc::termios,
}
impl Drop for Terminal {
    fn drop(&mut self) {
        // Restore both terminal input and cursor visibility on cancellation/errors.
        unsafe {
            libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &self.original);
        }
        let _ = write!(self.file, "\x1b[?25h\r\n");
        let _ = self.file.flush();
    }
}
fn ready(fd: RawFd) -> Result<bool> {
    // Darwin's poll can report /dev/tty as readable with no input available.
    ensure!(
        fd >= 0 && (fd as usize) < libc::FD_SETSIZE,
        "invalid terminal descriptor"
    );
    let mut read = unsafe { std::mem::zeroed::<libc::fd_set>() };
    let mut timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 150_000,
    };
    let result = unsafe {
        libc::FD_ZERO(&mut read);
        libc::FD_SET(fd, &mut read);
        libc::select(
            fd + 1,
            &mut read,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut timeout,
        )
    };
    ensure!(result >= 0, "cannot read selection key");
    Ok(result > 0)
}
fn byte(file: &mut File) -> Result<u8> {
    let mut b = [0];
    file.read_exact(&mut b)?;
    Ok(b[0])
}

pub fn choose(items: &[String], label: &str, output: &crate::Output) -> Result<usize> {
    ensure!(!items.is_empty(), "no {label} available");
    ensure!(
        !output.structured(),
        "specify {label} explicitly with structured output"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .with_context(|| format!("selection requires a terminal; specify {label} explicitly"))?;
    ensure!(file.is_terminal(), "selection requires a terminal");
    let fd = file.as_raw_fd();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    ensure!(
        unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } == 0,
        "cannot read terminal settings"
    );
    let original = unsafe { original.assume_init() };
    let mut tty = Terminal { file, original };
    let mut raw = original;
    raw.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG);
    raw.c_cc[libc::VMIN] = 1;
    raw.c_cc[libc::VTIME] = 0;
    ensure!(
        unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &raw) } == 0,
        "cannot configure selection terminal"
    );
    let mut size = std::mem::MaybeUninit::<libc::winsize>::zeroed();
    let width = if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, size.as_mut_ptr()) } == 0 {
        unsafe { size.assume_init() }.ws_col as usize
    } else {
        80
    };
    let width = if width < 20 { 80 } else { width };
    // Escape control/non-ASCII bytes so filenames cannot inject terminal control sequences
    // and every rendered character occupies exactly one column.
    let labels = items
        .iter()
        .map(|s| {
            s.chars()
                .flat_map(char::escape_default)
                .take(width - 5)
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    write!(
        tty.file,
        "Select {label} (Up/Down, Enter; Esc cancels)\r\n\x1b[?25l"
    )?;
    let rows = items.len().min(8);
    let mut selected: usize = 0;
    let mut first = true;
    loop {
        if !first {
            write!(tty.file, "\x1b[{rows}A")?;
        }
        first = false;
        let start = selected.saturating_sub(rows - 1);
        for (i, label) in labels.iter().enumerate().skip(start).take(rows) {
            write!(
                tty.file,
                "\r\x1b[2K{} {}\r\n",
                if selected == i { ">" } else { " " },
                label
            )?;
        }
        tty.file.flush()?;
        match byte(&mut tty.file)? {
            b'\r' | b'\n' => return Ok(selected),
            3 | 4 | 26 | b'q' => anyhow::bail!("selection cancelled"),
            b'k' => selected = selected.checked_sub(1).unwrap_or(items.len() - 1),
            b'j' => selected = (selected + 1) % items.len(),
            27 => {
                if !ready(fd)? {
                    anyhow::bail!("selection cancelled");
                }
                let prefix = byte(&mut tty.file)?;
                if !matches!(prefix, b'[' | b'O') || !ready(fd)? {
                    anyhow::bail!("selection cancelled");
                }
                match byte(&mut tty.file)? {
                    b'A' => selected = selected.checked_sub(1).unwrap_or(items.len() - 1),
                    b'B' => selected = (selected + 1) % items.len(),
                    _ => (),
                }
            }
            _ => (),
        }
    }
}
