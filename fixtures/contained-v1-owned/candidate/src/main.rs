mod check;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\"');
    out
}

fn parse_value(path: &Path) -> Result<i64, String> {
    let raw = fs::read_to_string(path).map_err(|_| "read vector")?;
    let text = raw.trim();
    let value = text
        .strip_prefix("{\"value\":")
        .and_then(|rest| rest.strip_suffix('}'))
        .ok_or("vector shape")?;
    value.parse::<i64>().map_err(|_| "vector value".to_owned())
}

fn collect_vectors(directory: &Path) -> Result<Vec<(String, i64)>, String> {
    let mut rows = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| "read vectors")? {
        let path = entry.map_err(|_| "read vector entry")?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json")
            || path.file_name().and_then(|value| value.to_str()) == Some("MANIFEST.json")
        {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or("vector id")?
            .to_owned();
        rows.push((id, parse_value(&path)?));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    if rows.is_empty() {
        return Err("empty vectors".to_owned());
    }
    Ok(rows)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || args[2] != "--json" {
        return Err("usage: corpus-adequacy-owned-fixture <vectors> --json <report>".to_owned());
    }
    let mut encoded = Vec::new();
    for (id, value) in collect_vectors(Path::new(&args[1]))? {
        let (accepted, reason, detail) = check::check(value, 10);
        encoded.push(format!(
            "{{\"accepted\":{},\"detail\":{},\"id\":{},\"reason\":{}}}",
            accepted,
            json_string(&detail),
            json_string(&id),
            json_string(reason),
        ));
    }
    let document = format!("{{\"vectors\":[{}]}}\n", encoded.join(","));
    fs::write(PathBuf::from(&args[3]), document).map_err(|_| "write report".to_owned())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        process::exit(2);
    }
}
