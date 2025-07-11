use std::env;
use std::fs;
use std::io::{self, Write, Read};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{SystemTime, Duration};
use std::path::{Path, PathBuf};
use std::hash::Hasher;
use rustc_hash::FxHasher;

use nix::unistd::{setgid, setuid, Gid, Uid, getuid, User};
use pam::Client;
use rpassword;
use termios::{Termios, TCSANOW, ICANON, ECHO};
use scopeguard::guard;
use libc;

const PERSIST_DIR: &str = "/var/run/doas";
const PERSIST_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, PartialEq)]
enum RuleAction {
    Permit,
    Deny,
}

#[derive(Debug)]
struct Rule {
    user: String,
    target: Option<String>,
    cmd: Option<String>,
    args: Option<Vec<String>>,
    action: RuleAction,
    persist: bool,
    nopass: bool,
}

enum RuleMatch {
    Permitted { target: String, persist: bool, nopass: bool },
    Denied,
}

fn is_setuid_root() -> bool {
    Uid::effective().is_root()
}

fn get_user_groups(user: &str) -> Vec<String> {
    let output = Command::new("id")
        .arg("-Gn")
        .arg(user)
        .output()
        .expect("failed to get groups");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(|s| s.to_string())
        .collect()
}

fn drop_privileges(target: &str) {
    let target_pw = User::from_name(target).expect("target lookup failed").expect("no such user");
    setgid(Gid::from_raw(target_pw.gid.as_raw())).expect("setgid failed");
    setuid(Uid::from_raw(target_pw.uid.as_raw())).expect("setuid failed");
}

fn parse_config(config: &str) -> Vec<Rule> {
    config
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.is_empty() {
                return None;
            }

            let action: RuleAction;
            let mut user_str = String::new();
            let mut target = None;
            let mut cmd = None;
            let mut args = None;
            let mut persist = false;
            let mut nopass = false;

            let mut i = 0;

            if let Some(action_token) = parts.get(i) {
                action = match *action_token {
                    "permit" => RuleAction::Permit,
                    "deny" => RuleAction::Deny,
                    _ => {
                        eprintln!("doas: warning: invalid action '{action_token}' in config line: {}", line);
                        return None;
                    },
                };
                i += 1;
            } else {
                return None;
            }

            while i < parts.len() {
                match parts[i] {
                    "persist" => {
                        persist = true;
                    },
                    "nopass" => {
                        nopass = true;
                    },
                    "as" => {
                        i += 1;
                        if let Some(target_token) = parts.get(i) {
                            target = Some(target_token.to_string());
                        } else {
                            eprintln!("doas: warning: 'as' without target in config line: {}", line);
                            return None;
                        }
                    },
                    "cmd" => {
                        i += 1;
                        if let Some(cmd_token) = parts.get(i) {
                            cmd = Some(cmd_token.to_string());
                        } else {
                            eprintln!("doas: warning: 'cmd' without command in config line: {}", line);
                            return None;
                        }
                    },
                    "args" => {
                        i += 1;
                        if i < parts.len() {
                            args = Some(parts[i..].iter().map(|s| s.to_string()).collect());
                            break;
                        } else {
                            eprintln!("doas: warning: 'args' without arguments in config line: {}", line);
                            return None;
                        }
                    },
                    _ => {
                        if user_str.is_empty() {
                            user_str = parts[i].to_string();
                        } else {
                            eprintln!("doas: warning: unrecognized token or misplaced user '{:?}' in config line: {}", parts[i], line);
                        }
                    },
                }
                i += 1;
            }

            if user_str.is_empty() {
                eprintln!("doas: warning: rule missing user/group in config line: {}", line);
                return None;
            }

            Some(Rule {
                user: user_str,
                target,
                cmd,
                args,
                action,
                persist,
                nopass,
            })
        })
        .collect()
}

fn evaluate_rules(
    rules: &[Rule],
    current_user: &str,
    groups: &[String],
    target: Option<&str>,
    command_args: &[String],
) -> RuleMatch {
    let debug = env::var("DOAS_DEBUG").is_ok();

    if debug {
        eprintln!("DEBUG: current_user = {:?}", current_user);
        eprintln!("DEBUG: groups = {:?}", groups);
        eprintln!("DEBUG: target = {:?}", target);
        eprintln!("DEBUG: command_args = {:?}", command_args);
    }

    let mut last_match: Option<&Rule> = None;

    for rule in rules {
        if debug {
            eprintln!("DEBUG: checking rule = {:?}", rule);
        }

        let user_matches = rule.user == current_user;
        let group_matches = rule.user.starts_with(':') && groups.contains(&rule.user[1..].to_string());

        if !(user_matches || group_matches) {
            if debug { eprintln!("DEBUG: User/group mismatch: rule_user={:?}, current_user={:?}, groups={:?}", rule.user, current_user, groups); }
            continue;
        }

        if let Some(ref tgt) = rule.target {
            if Some(tgt.as_str()) != target {
                if debug { eprintln!("DEBUG: Target mismatch: rule_target={:?}, actual_target={:?}", tgt, target); }
                continue;
            }
        } else {
            if debug { eprintln!("DEBUG: Rule has no target, allows any."); }
        }

        if let Some(ref c) = rule.cmd {
            if command_args.is_empty() || &command_args[0] != c {
                if debug { eprintln!("DEBUG: Command mismatch: rule_cmd={:?}, actual_cmd={:?}", c, command_args.first()); }
                continue;
            }
            if let Some(ref expected_args) = rule.args {
                if &command_args[1..] != expected_args.as_slice() {
                    if debug { eprintln!("DEBUG: Args mismatch: rule_args={:?}, actual_args={:?}", expected_args, &command_args[1..]); }
                    continue;
                }
            }
        } else {
            if debug { eprintln!("DEBUG: Rule has no command, matches any command."); }
        }

        last_match = Some(rule);
    }

    if let Some(rule) = last_match {
        match rule.action {
            RuleAction::Permit => RuleMatch::Permitted {
                target: target.unwrap_or("root").to_string(),
                persist: rule.persist,
                nopass: rule.nopass,
            },
            RuleAction::Deny => RuleMatch::Denied,
        }
    } else {
        RuleMatch::Denied
    }
}

fn prompt_password() -> String {
    let mut password = String::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    print!("\x1b[31m[AUTH]\x1b[0m Password: ");
    stdout.flush().unwrap();

    let maybe_termios = Termios::from_fd(0);

    if let Ok(mut termios) = maybe_termios {
        let original_termios = termios;
        termios.c_lflag &= !(ICANON | ECHO);
        termios::tcsetattr(0, TCSANOW, &termios).expect("failed to set terminal attributes");

        let _restore_termios = guard(original_termios, |original_termios| {
            termios::tcsetattr(0, TCSANOW, &original_termios).expect("failed to restore terminal attributes");
        });

        for c in stdin.bytes() {
            match c {
                Ok(b'\n') | Ok(b'\r') => {
                    break;
                },
                Ok(127) => {
                    if !password.is_empty() {
                        password.pop();
                        print!("\x08 \x08");
                        stdout.flush().unwrap();
                    }
                },
                Ok(byte) => {
                    if let Some(ch) = char::from_u32(byte as u32) {
                        password.push(ch);
                        print!("*");
                        stdout.flush().unwrap();
                    }
                },
                Err(_) => break,
            }
        }
        println!();
        print!("\r");
        for _ in 0..(password.len() + "[AUTH] Password: ".len() + "\x1b[31m\x1b[0m".len()) {
            print!(" ");
        }
        print!("\r");
        stdout.flush().unwrap();

    } else {
        eprintln!("doas: warning: could not configure terminal for asterisk echo, falling back to no-echo.");
        return rpassword::read_password().unwrap_or_default();
    }

    password
}

fn authenticate_user(user: &str) -> bool {
    let password = prompt_password();

    let mut client = Client::with_password("login").expect("PAM initialization failed");
    client.conversation_mut().set_credentials(user, &password);
    client.authenticate().is_ok() && client.open_session().is_ok()
}

fn get_tty_name_hash() -> Option<String> {
    let debug = env::var("DOAS_DEBUG").is_ok();
    let mut buf = [0 as libc::c_char; 256];
    let tty_fd = libc::STDIN_FILENO;

    unsafe {
        let result = libc::ttyname_r(tty_fd, buf.as_mut_ptr(), buf.len());
        if result == 0 {
            let c_str = std::ffi::CStr::from_ptr(buf.as_ptr());
            let tty_str = c_str.to_string_lossy().into_owned();
            if debug { eprintln!("DEBUG: Current TTY: {:?}", tty_str); }

            let mut hasher = FxHasher::default();
            hasher.write(tty_str.as_bytes());
            Some(format!("{:x}", hasher.finish()))
        } else {
            if debug { eprintln!("DEBUG: Could not get TTY name (errno: {}).", result); }
            None
        }
    }
}

fn get_persist_file_path(user: &str) -> Option<PathBuf> {
    let debug = env::var("DOAS_DEBUG").is_ok();
    if let Some(tty_hash) = get_tty_name_hash() {
        let persist_file_name = format!("{}-{}", user, tty_hash);
        Some(Path::new(PERSIST_DIR).join(persist_file_name))
    } else {
        if debug { eprintln!("doas: warning: persist requested but could not determine TTY for token file."); }
        None
    }
}

fn check_persist_token(persist_file_path: &Path) -> bool {
    let debug = env::var("DOAS_DEBUG").is_ok();
    let now = SystemTime::now();

    if persist_file_path.exists() {
        if let Ok(metadata) = fs::metadata(&persist_file_path) {
            if let Ok(modified) = metadata.modified() {
                let duration_since_modified = now.duration_since(modified).unwrap_or_default();
                if debug { eprintln!("DEBUG: Persist file modified: {:?}, Duration since modified: {:?}", modified, duration_since_modified); }
                if duration_since_modified < Duration::from_secs(PERSIST_TIMEOUT_SECS) {
                    if debug { eprintln!("DEBUG: Persist token is VALID."); }
                    return true;
                } else {
                    if debug { eprintln!("DEBUG: Persist token is EXPIRED."); }
                    let _ = fs::remove_file(persist_file_path).map_err(|e| { if debug { eprintln!("doas: warning: could not remove expired persist file {}: {e}", persist_file_path.display()); }});
                }
            } else {
                if debug { eprintln!("DEBUG: Could not get modified timestamp for persist file."); }
            }
        } else {
            if debug { eprintln!("DEBUG: Could not get metadata for persist file."); }
        }
    } else {
        if debug { eprintln!("DEBUG: Persist file does not exist."); }
    }
    false
}

fn update_persist_token(persist_file_path: &Path) {
    let debug = env::var("DOAS_DEBUG").is_ok();
    let _ = fs::create_dir_all(PERSIST_DIR).map_err(|e| { if debug { eprintln!("doas: warning: could not create persist directory: {e}"); }});
    let _ = fs::File::create(persist_file_path)
        .and_then(|file| {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = file.metadata()?.permissions();
                perms.set_mode(0o600);
                file.set_permissions(perms)?;
            }
            Ok(())
        })
        .map_err(|e| { if debug { eprintln!("doas: warning: could not update persist file {}: {e}", persist_file_path.display()); }});
    if debug { eprintln!("DEBUG: Persist token UPDATED at {:?}", persist_file_path); }
}

fn main() {
    let debug = env::var("DOAS_DEBUG").is_ok();

    if !is_setuid_root() {
        eprintln!("doas: not installed setuid");
        std::process::exit(1);
    }

    let args: Vec<String> = env::args().collect();

    if args.len() == 2 && (args[1] == "--version" || args[1] == "-v") {
        println!("doas-rs 0.1.1");
        std::process::exit(0);
    }

    if args.len() < 2 {
        eprintln!("usage: doas [-s] [-u user] command [args...]");
        std::process::exit(1);
    }

    let config_path = "/etc/doas.conf";
    let config_data = fs::read_to_string(config_path).expect("doas: could not read config");
    let rules = parse_config(&config_data);

    let real_uid = getuid();
    let current_user = User::from_uid(real_uid)
        .expect("failed to get user from uid")
        .expect("no user found")
        .name;
    let groups = get_user_groups(&current_user);

    let mut target_user: Option<String> = None;
    let mut shell_mode = false;
    let mut cmd_start = 1;

    while cmd_start < args.len() {
        match args[cmd_start].as_str() {
            "-u" => {
                if cmd_start + 1 >= args.len() {
                    eprintln!("doas: missing argument for -u");
                    std::process::exit(1);
                }
                target_user = Some(args[cmd_start + 1].clone());
                cmd_start += 2;
            }
            "-s" => {
                shell_mode = true;
                cmd_start += 1;
            }
            _ => break,
        }
    }

    let command_args: Vec<String> = if shell_mode {
        let shell = env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        vec![shell]
    } else {
        args[cmd_start..].to_vec()
    };

    if command_args.is_empty() {
        eprintln!("doas: no command given");
        std::process::exit(1);
    }

    let rule_match = evaluate_rules(
        &rules,
        &current_user,
        &groups,
        target_user.as_deref(),
        &command_args,
    );

    match rule_match {
        RuleMatch::Permitted { target, persist, nopass } => {
            let mut authenticated = false;
            let persist_file_path_opt = get_persist_file_path(&current_user);

            if persist {
                if let Some(ref pfp) = persist_file_path_opt {
                    authenticated = check_persist_token(pfp);
                } else {
                    if debug { eprintln!("doas: warning: persist requested but could not determine TTY for token file. Authentication always required."); }
                }
            }
            
            if !authenticated && nopass {
                authenticated = true;
                if debug { eprintln!("DEBUG: Authenticated via nopass."); }
            }

            if !authenticated {
                if debug { eprintln!("DEBUG: Prompting for authentication."); }
                for attempt in 0..3 {
                    if authenticate_user(&current_user) {
                        authenticated = true;
                        if debug { eprintln!("DEBUG: Authentication successful."); }
                        if persist {
                            if let Some(ref pfp) = persist_file_path_opt {
                                update_persist_token(pfp);
                            }
                        }
                        break;
                    } else {
                        eprintln!("doas: authentication failed");
                        if attempt == 2 {
                            std::process::exit(1);
                        }
                    }
                }
            }

            if !authenticated {
                eprintln!("doas: authentication failed.");
                std::process::exit(1);
            }

            let mut command_builder = Command::new(&command_args[0]);
            command_builder.args(&command_args[1..]);

            drop_privileges(&target);
            let err = command_builder.exec();
            eprintln!("doas: exec failed: {err}");
            std::process::exit(1);
        }
        RuleMatch::Denied => {
            eprintln!("doas: permission denied");
            std::process::exit(1);
        }
    }
}
