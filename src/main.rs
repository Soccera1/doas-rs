use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

use nix::unistd::{setgid, setuid, Gid, Uid, getuid, User};
use pam::Client;
use rpassword;

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
}

enum RuleMatch {
    Permitted { target: String, persist: bool },
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
            let mut parts = line.split_whitespace();

            let action_str = parts.next()?;
            let action = match action_str {
                "permit" => RuleAction::Permit,
                "deny" => RuleAction::Deny,
                _ => return None,
            };

            let user = parts.next()?.to_string();

            let mut target = None;
            let mut cmd = None;
            let mut args = None;
            let mut persist = false;

            while let Some(token) = parts.next() {
                match token {
                    "as" => target = parts.next().map(|s| s.to_string()),
                    "cmd" => cmd = parts.next().map(|s| s.to_string()),
                    "args" => args = parts.next().map(|s| vec![s.to_string()]),
                    "persist" => persist = true,
                    _ => {}
                }
            }

            Some(Rule {
                user,
                target,
                cmd,
                args,
                action,
                persist,
            })
        })
        .collect()
}

fn evaluate_rules(
    rules: &[Rule],
    current_user: &str,
    _groups: &[String],
    target: Option<&str>,
    command_args: &[String],
) -> RuleMatch {
    let debug = env::var("DOAS_DEBUG").is_ok();

    if debug {
        eprintln!("DEBUG: current_user = {:?}", current_user);
        eprintln!("DEBUG: target = {:?}", target);
        eprintln!("DEBUG: command_args = {:?}", command_args);
    }

    let mut last_match: Option<&Rule> = None;

    for rule in rules {
        if debug {
            eprintln!("DEBUG: checking rule = {:?}", rule);
        }

        if rule.user != current_user {
            continue;
        }
        if let Some(ref tgt) = rule.target {
            if Some(tgt.as_str()) != target {
                continue;
            }
        }
        if let Some(ref c) = rule.cmd {
            if command_args.is_empty() || &command_args[0] != c {
                continue;
            }
            if let Some(ref expected_args) = rule.args {
                if &command_args[1..] != expected_args.as_slice() {
                    continue;
                }
            }
        }

        last_match = Some(rule);
    }

    if let Some(rule) = last_match {
        match rule.action {
            RuleAction::Permit => RuleMatch::Permitted {
                target: target.unwrap_or("root").to_string(),
                persist: rule.persist,
            },
            RuleAction::Deny => RuleMatch::Denied,
        }
    } else {
        RuleMatch::Denied
    }
}

fn prompt_password() -> String {
    print!("\x1b[31m[AUTH]\x1b[0m Password: ");
    io::stdout().flush().unwrap();
    rpassword::read_password().unwrap_or_default()
}

fn authenticate_user(user: &str) -> bool {
    let password = prompt_password();

    let mut client = Client::with_password("login").expect("PAM initialization failed");
    client.conversation_mut().set_credentials(user, &password);
    client.authenticate().is_ok() && client.open_session().is_ok()
}

fn main() {
    if !is_setuid_root() {
        eprintln!("doas: not installed setuid");
        std::process::exit(1);
    }

    let args: Vec<String> = env::args().collect();
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
        RuleMatch::Permitted { target, persist } => {
            for attempt in 0..3 {
                if authenticate_user(&current_user) {
                    break;
                } else {
                    eprintln!("doas: authentication failed");
                    if attempt == 2 {
                        std::process::exit(1);
                    }
                }
            }

            if persist {
                eprintln!("Warning: persist option enabled but not implemented");
            }

            drop_privileges(&target);
            let err = Command::new(&command_args[0])
                .args(&command_args[1..])
                .exec();
            eprintln!("doas: exec failed: {err}");
            std::process::exit(1);
        }
        RuleMatch::Denied => {
            eprintln!("doas: permission denied");
            std::process::exit(1);
        }
    }
}
