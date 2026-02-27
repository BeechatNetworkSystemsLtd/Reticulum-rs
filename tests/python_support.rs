use std::{env, path::PathBuf, process::Command};

fn manifest_dir() -> &'static str {
    env!("CARGO_MANIFEST_DIR")
}

fn python_path_env() -> String {
    let reference = PathBuf::from(manifest_dir()).join("reference").join("Reticulum");
    match env::var("PYTHONPATH") {
        Ok(existing) if !existing.is_empty() => format!("{}:{}", reference.display(), existing),
        _ => reference.display().to_string(),
    }
}

fn python_command() -> Command {
    let mut cmd = Command::new("python3");
    cmd.env("PYTHONPATH", python_path_env());
    cmd.current_dir(manifest_dir());
    cmd
}

pub fn python_available() -> bool {
    python_command()
        .arg("-c")
        .arg("import RNS")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub fn run_python(args: &[&str]) -> (i32, String, String) {
    let mut cmd = python_command();

    if let Some((script, rest)) = args.split_first() {
        let script_path = PathBuf::from(manifest_dir()).join(script);
        cmd.arg(script_path);
        cmd.args(rest);
    }

    let out = cmd.output().expect("failed to run python3");

    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}
