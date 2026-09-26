//! LogSync pack tokenizer - the sandboxed twin of backend/logsync/core/tokenize.py.
//!
//! Compiled to wasm32-unknown-unknown, this module has no imports: no WASI, no
//! files, no network, no clock. The host (backend/logsync/core/wasm_host.py)
//! runs it in Wasmtime with a fuel budget and a memory limit.
//!
//! ABI (all lengths in bytes, JSON is UTF-8):
//!   ls_alloc(len) -> ptr              reserve guest memory for the host to write into
//!   ls_free(ptr, len)                 release it
//!   ls_load(spec_ptr, spec_len) -> h  compile a pack spec; handle >= 0, or -1 on error
//!                                     spec = format RS header RS patterns RS columns RS delimiter
//!                                     (RS = 0x1E between parts, US = 0x1F between list items)
//!   ls_tokenize(h, ptr, len) -> u64   tokenize one event; returns (result_ptr << 32) | result_len
//!   ls_tokenize_batch(h, ptr, len)    many events in one call: input is repeated
//!                                     [u32 little-endian length][bytes]; output a JSON array
//!
//! The algorithms must stay identical to the Python reference; a differential
//! test over the whole sample corpus (tests/test_wasm.py) enforces it.

use regex::bytes::{Regex, RegexBuilder};
use std::cell::RefCell;

const PLAIN: u8 = 0;
const JSON_STRING: u8 = 1;
const CSV_QUOTED: u8 = 2;
const CEF_ESCAPED: u8 = 3;

const CEF_HEADER: [&str; 7] = ["cef.version", "cef.vendor", "cef.product", "cef.device_version",
                               "cef.signature_id", "cef.name", "cef.severity"];
const LEEF_HEADER: [&str; 5] = ["leef.version", "leef.vendor", "leef.product",
                                "leef.product_version", "leef.event_id"];

enum Format { Regex(Vec<Regex>), Kv, Csv(Vec<String>), Cef, Leef(Vec<u8>), Json }

pub struct Spec { header: Option<Regex>, format: Format }

#[derive(Debug, PartialEq)]
pub struct TokenResult {
    pub ok: bool,
    pub fields: Vec<(String, usize, usize, u8)>,
    pub unexplained: Vec<(usize, usize)>,
    pub error: Option<String>,
}

type Fields = Vec<(String, usize, usize, u8)>;
type Spans = Vec<(usize, usize)>;

fn compile(p: &str) -> Result<Regex, String> {
    // unicode(false): ASCII \d \w \s and byte-wise '.', like Python's bytes regexes.
    RegexBuilder::new(p).unicode(false).build().map_err(|e| e.to_string())
}

pub fn load_spec(raw: &[u8]) -> Result<Spec, String> {
    let text = std::str::from_utf8(raw).map_err(|e| e.to_string())?;
    let parts: Vec<&str> = text.split('\u{1e}').collect();
    if parts.len() != 5 { return Err("spec must have 5 parts".into()); }
    let list = |s: &str| -> Vec<String> {
        if s.is_empty() { vec![] } else { s.split('\u{1f}').map(String::from).collect() }
    };
    let header = if parts[1].is_empty() { None } else { Some(compile(parts[1])?) };
    let format = match parts[0] {
        "regex" => Format::Regex(list(parts[2]).iter().map(|p| compile(p)).collect::<Result<_, _>>()?),
        "kv" => Format::Kv,
        "csv" => Format::Csv(list(parts[3])),
        "cef" => Format::Cef,
        "leef" => Format::Leef(if parts[4].is_empty() { b"\t".to_vec() } else { parts[4].as_bytes().to_vec() }),
        "json" => Format::Json,
        other => return Err(format!("unknown format {:?}", other)),
    };
    Ok(Spec { header, format })
}

/// Serialize a result as JSON by hand (no serde inside the sandbox).
/// Characters outside printable ASCII are \u-escaped; names are Latin-1 or
/// lossily decoded UTF-8, so everything stays within the Basic Multilingual Plane.
pub fn to_json(r: &TokenResult) -> String {
    fn esc(s: &str, out: &mut String) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 || (c as u32) > 0x7e => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }
    let mut o = String::with_capacity(64 + r.fields.len() * 32);
    o.push_str(if r.ok { "{\"ok\":true,\"fields\":[" } else { "{\"ok\":false,\"fields\":[" });
    for (i, (name, s, e, k)) in r.fields.iter().enumerate() {
        if i > 0 { o.push(','); }
        o.push('[');
        esc(name, &mut o);
        o.push_str(&format!(",{},{},{}]", s, e, k));
    }
    o.push_str("],\"unexplained\":[");
    for (i, (s, e)) in r.unexplained.iter().enumerate() {
        if i > 0 { o.push(','); }
        o.push_str(&format!("[{},{}]", s, e));
    }
    o.push_str("],\"error\":");
    match &r.error { Some(e) => esc(e, &mut o), None => o.push_str("null") }
    o.push('}');
    o
}

// ------------------------------------------------------------------ helpers
fn find(data: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if start > data.len() || needle.is_empty() { return None; }
    data[start..].windows(needle.len()).position(|w| w == needle).map(|i| i + start)
}

fn find_byte(data: &[u8], b: u8, start: usize) -> Option<usize> {
    if start > data.len() { return None; }
    data[start..].iter().position(|&c| c == b).map(|i| i + start)
}

fn latin1(bytes: &[u8]) -> String { bytes.iter().map(|&b| b as char).collect() }

/// Anchored match at `pos` (Python's pattern.match(data, pos)).
fn match_at<'a>(re: &Regex, data: &'a [u8], pos: usize) -> Option<regex::bytes::Captures<'a>> {
    re.captures_at(data, pos).filter(|c| c.get(0).map_or(false, |m| m.start() == pos))
}

fn groups(re: &Regex, caps: &regex::bytes::Captures, out: &mut Fields) {
    for (i, name) in re.capture_names().enumerate() {
        if let (Some(name), Some(m)) = (name, caps.get(i)) {
            out.push((name.to_string(), m.start(), m.end(), PLAIN));
        }
    }
}

// ------------------------------------------------------------------ entry
pub fn tokenize(spec: &Spec, data: &[u8]) -> TokenResult {
    let mut fields: Fields = Vec::new();
    let mut unexplained: Spans = Vec::new();
    let res = (|| -> Result<(), String> {
        let mut pos = 0;
        if let Some(h) = &spec.header {
            let caps = match_at(h, data, 0).ok_or("header did not match")?;
            groups(h, &caps, &mut fields);
            pos = caps.get(0).unwrap().end();
        }
        match &spec.format {
            Format::Regex(pats) => regex_body(pats, data, pos, &mut fields, &mut unexplained),
            Format::Kv => { kv(data, pos, &mut fields, &mut unexplained); Ok(()) }
            Format::Csv(cols) => { csv(cols, data, pos, &mut fields, &mut unexplained); Ok(()) }
            Format::Cef => cef(data, pos, &mut fields, &mut unexplained),
            Format::Leef(d) => leef(d, data, pos, &mut fields, &mut unexplained),
            Format::Json => json_body(data, pos, &mut fields, &mut unexplained),
        }
    })();
    match res {
        Err(e) => TokenResult { ok: false, fields: vec![], unexplained: vec![], error: Some(e) },
        Ok(()) => {
            fields.sort_by(|a, b| (a.1, a.2, &a.0).cmp(&(b.1, b.2, &b.0)));
            TokenResult { ok: true, fields, unexplained, error: None }
        }
    }
}

// ------------------------------------------------------------------ regex
fn regex_body(pats: &[Regex], data: &[u8], pos: usize, f: &mut Fields, u: &mut Spans) -> Result<(), String> {
    let n = data.len();
    let mut best: Option<(usize, regex::bytes::Captures)> = None;
    for (i, re) in pats.iter().enumerate() {
        if let Some(c) = match_at(re, data, pos) {
            let end = c.get(0).unwrap().end();
            if end == n { groups(re, &c, f); return Ok(()); }
            let better = match &best { None => true, Some((_, b)) => end > b.get(0).unwrap().end() };
            if better { best = Some((i, c)); }
        }
    }
    let (i, c) = best.ok_or("no pattern matched")?;
    groups(&pats[i], &c, f);
    u.push((c.get(0).unwrap().end(), n));
    Ok(())
}

// ------------------------------------------------------------------ key=value
fn is_kv_key(b: u8) -> bool { b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-' }

fn kv(data: &[u8], mut pos: usize, f: &mut Fields, u: &mut Spans) {
    let n = data.len();
    while pos < n {
        if data[pos] == b' ' { pos += 1; continue; }
        let mut k = pos;
        while k < n && is_kv_key(data[k]) { k += 1; }
        if k == pos || k >= n || data[k] != b'=' { u.push((pos, n)); return; }
        let key = latin1(&data[pos..k]);
        let key_start = pos;
        pos = k + 1;
        if pos < n && data[pos] == b'"' {
            match find_byte(data, b'"', pos + 1) {
                None => { u.push((key_start, n)); return; }
                Some(q) => { f.push((key, pos + 1, q, PLAIN)); pos = q + 1; }
            }
        } else {
            let end = find_byte(data, b' ', pos).unwrap_or(n);
            f.push((key, pos, end, PLAIN));
            pos = end;
        }
    }
}

// ------------------------------------------------------------------ CSV
fn csv(cols: &[String], data: &[u8], mut pos: usize, f: &mut Fields, u: &mut Spans) {
    let n = data.len();
    let mut col = 0;
    loop {
        let name = if col < cols.len() { cols[col].clone() } else { format!("col{}", col) };
        if pos < n && data[pos] == b'"' {
            let mut i = pos + 1;
            while i < n {
                if data[i] == b'"' {
                    if i + 1 < n && data[i + 1] == b'"' { i += 2; continue; }
                    break;
                }
                i += 1;
            }
            if i >= n { u.push((pos, n)); return; }
            f.push((name, pos + 1, i, CSV_QUOTED));
            pos = i + 1;
        } else {
            let end = find_byte(data, b',', pos).unwrap_or(n);
            f.push((name, pos, end, PLAIN));
            pos = end;
        }
        col += 1;
        if pos >= n { return; }
        if data[pos] == b',' { pos += 1; continue; }
        u.push((pos, n));
        return;
    }
}

// ------------------------------------------------------------------ CEF
fn unescaped(data: &[u8], b: u8, start: usize) -> Option<usize> {
    let mut i = find_byte(data, b, start);
    while let Some(j) = i {
        if j > 0 && data[j - 1] == b'\\' { i = find_byte(data, b, j + 1); } else { break; }
    }
    i
}

fn cef_key_at(data: &[u8], i: usize) -> Option<usize> {
    let mut k = i;
    while k < data.len() && (data[k].is_ascii_alphanumeric() || data[k] == b'_') { k += 1; }
    if k > i && k < data.len() && data[k] == b'=' { Some(k + 1) } else { None }
}

fn cef(data: &[u8], mut pos: usize, f: &mut Fields, u: &mut Spans) -> Result<(), String> {
    let n = data.len();
    if !data[pos..].starts_with(b"CEF:") { return Err("not a CEF message".into()); }
    pos += 4;
    for name in CEF_HEADER {
        let bar = unescaped(data, b'|', pos).ok_or_else(|| format!("CEF header truncated at {}", name))?;
        f.push((name.to_string(), pos, bar, CEF_ESCAPED));
        pos = bar + 1;
    }
    let mut keys: Vec<(String, usize, usize)> = Vec::new();
    for i in pos..n {
        if i == pos || data[i - 1] == b' ' {
            if let Some(vstart) = cef_key_at(data, i) {
                keys.push((latin1(&data[i..vstart - 1]), i, vstart));
            }
        }
    }
    if keys.is_empty() {
        if pos < n { u.push((pos, n)); }
        return Ok(());
    }
    if keys[0].1 != pos { u.push((pos, keys[0].1)); }
    for j in 0..keys.len() {
        let vend = if j + 1 < keys.len() { keys[j + 1].1 - 1 } else { n };
        f.push((keys[j].0.clone(), keys[j].2, vend, CEF_ESCAPED));
    }
    Ok(())
}

// ------------------------------------------------------------------ LEEF 1.0
fn leef(delim: &[u8], data: &[u8], mut pos: usize, f: &mut Fields, u: &mut Spans) -> Result<(), String> {
    let n = data.len();
    if !data[pos..].starts_with(b"LEEF:") { return Err("not a LEEF message".into()); }
    pos += 5;
    for name in LEEF_HEADER {
        let bar = find_byte(data, b'|', pos).ok_or_else(|| format!("LEEF header truncated at {}", name))?;
        f.push((name.to_string(), pos, bar, PLAIN));
        pos = bar + 1;
    }
    while pos < n {
        let end = find(data, delim, pos).unwrap_or(n);
        if end > pos {
            match data[pos..end].iter().position(|&c| c == b'=') {
                None => u.push((pos, end)),
                Some(e) => f.push((latin1(&data[pos..pos + e]), pos + e + 1, end, PLAIN)),
            }
        }
        pos = end + delim.len();
    }
    Ok(())
}

// ------------------------------------------------------------------ JSON
fn is_ws(b: u8) -> bool { matches!(b, b' ' | b'\t' | b'\r' | b'\n') }

fn ws(data: &[u8], mut pos: usize) -> usize {
    while pos < data.len() && is_ws(data[pos]) { pos += 1; }
    pos
}

fn json_body(data: &[u8], pos: usize, f: &mut Fields, u: &mut Spans) -> Result<(), String> {
    let n = data.len();
    let pos = ws(data, pos);
    if pos >= n || data[pos] != b'{' { return Err("JSON body must be an object".into()); }
    let pos = ws(data, jvalue(data, pos, "", f)?);
    if pos < n { u.push((pos, n)); }
    Ok(())
}

fn jstring_end(data: &[u8], pos: usize) -> Result<usize, String> {
    let mut i = pos + 1;
    while i < data.len() {
        match data[i] {
            b'\\' => i += 2,
            b'"' => return Ok(i),
            _ => i += 1,
        }
    }
    Err("unterminated JSON string".into())
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() { key.to_string() } else { format!("{}.{}", path, key) }
}

fn is_json_number(t: &[u8]) -> bool {
    // -?\d+(\.\d+)?([eE][+-]?\d+)?
    let mut i = 0;
    let digits = |i: &mut usize| { let s = *i; while *i < t.len() && t[*i].is_ascii_digit() { *i += 1; } *i > s };
    if i < t.len() && t[i] == b'-' { i += 1; }
    if !digits(&mut i) { return false; }
    if i < t.len() && t[i] == b'.' { i += 1; if !digits(&mut i) { return false; } }
    if i < t.len() && (t[i] == b'e' || t[i] == b'E') {
        i += 1;
        if i < t.len() && (t[i] == b'+' || t[i] == b'-') { i += 1; }
        if !digits(&mut i) { return false; }
    }
    i == t.len()
}

fn jvalue(data: &[u8], pos: usize, path: &str, f: &mut Fields) -> Result<usize, String> {
    let n = data.len();
    let mut pos = ws(data, pos);
    if pos >= n { return Err("unexpected end of JSON".into()); }
    match data[pos] {
        b'{' => {
            pos = ws(data, pos + 1);
            if pos < n && data[pos] == b'}' { return Ok(pos + 1); }
            loop {
                pos = ws(data, pos);
                if pos >= n || data[pos] != b'"' { return Err("expected JSON key".into()); }
                let kend = jstring_end(data, pos)?;
                let key = String::from_utf8_lossy(&data[pos + 1..kend]).into_owned();
                pos = ws(data, kend + 1);
                if pos >= n || data[pos] != b':' { return Err("expected ':'".into()); }
                pos = ws(data, jvalue(data, pos + 1, &join(path, &key), f)?);
                if pos < n && data[pos] == b',' { pos += 1; continue; }
                if pos < n && data[pos] == b'}' { return Ok(pos + 1); }
                return Err("expected ',' or '}'".into());
            }
        }
        b'[' => {
            pos = ws(data, pos + 1);
            if pos < n && data[pos] == b']' { return Ok(pos + 1); }
            let mut i = 0;
            loop {
                pos = ws(data, jvalue(data, pos, &join(path, &i.to_string()), f)?);
                i += 1;
                if pos < n && data[pos] == b',' { pos += 1; continue; }
                if pos < n && data[pos] == b']' { return Ok(pos + 1); }
                return Err("expected ',' or ']'".into());
            }
        }
        b'"' => {
            let end = jstring_end(data, pos)?;
            f.push((path.to_string(), pos + 1, end, JSON_STRING));
            Ok(end + 1)
        }
        _ => {
            let start = pos;
            while pos < n && !matches!(data[pos], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') { pos += 1; }
            let tok = &data[start..pos];
            if tok == b"true" || tok == b"false" || tok == b"null" || is_json_number(tok) {
                f.push((path.to_string(), start, pos, PLAIN));
                Ok(pos)
            } else {
                Err("invalid JSON value".into())
            }
        }
    }
}

// ------------------------------------------------------------------ WASM ABI
thread_local! {
    static SPECS: RefCell<Vec<Spec>> = RefCell::new(Vec::new());
}

#[no_mangle]
pub extern "C" fn ls_alloc(len: u32) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr`/`len` must come from `ls_alloc` or `ls_tokenize`.
#[no_mangle]
pub unsafe extern "C" fn ls_free(ptr: *mut u8, len: u32) {
    drop(Vec::from_raw_parts(ptr, 0, len as usize));
}

/// # Safety
/// `ptr`/`len` must describe memory the host wrote via `ls_alloc`.
#[no_mangle]
pub unsafe extern "C" fn ls_load(ptr: *const u8, len: u32) -> i32 {
    let json = std::slice::from_raw_parts(ptr, len as usize);
    match load_spec(json) {
        Ok(spec) => SPECS.with(|s| { let mut s = s.borrow_mut(); s.push(spec); (s.len() - 1) as i32 }),
        Err(_) => -1,
    }
}

/// # Safety
/// `ptr`/`len` must describe memory the host wrote via `ls_alloc`.
#[no_mangle]
pub unsafe extern "C" fn ls_tokenize(handle: i32, ptr: *const u8, len: u32) -> u64 {
    let data = std::slice::from_raw_parts(ptr, len as usize);
    let result = SPECS.with(|s| {
        let s = s.borrow();
        match s.get(handle as usize) {
            Some(spec) => tokenize(spec, data),
            None => TokenResult { ok: false, fields: vec![], unexplained: vec![], error: Some("bad handle".into()) },
        }
    });
    hand_out(to_json(&result).into_bytes())
}

/// # Safety
/// `ptr`/`len` must describe memory the host wrote via `ls_alloc`.
#[no_mangle]
pub unsafe extern "C" fn ls_tokenize_batch(handle: i32, ptr: *const u8, len: u32) -> u64 {
    let buf = std::slice::from_raw_parts(ptr, len as usize);
    let mut out = String::from("[");
    SPECS.with(|s| {
        let s = s.borrow();
        let mut pos = 0;
        let mut first = true;
        while pos + 4 <= buf.len() {
            let n = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
            pos += 4;
            let end = (pos + n).min(buf.len());
            let r = match s.get(handle as usize) {
                Some(spec) => tokenize(spec, &buf[pos..end]),
                None => TokenResult { ok: false, fields: vec![], unexplained: vec![], error: Some("bad handle".into()) },
            };
            if !first { out.push(','); }
            first = false;
            out.push_str(&to_json(&r));
            pos = end;
        }
    });
    out.push(']');
    hand_out(out.into_bytes())
}

fn hand_out(mut out: Vec<u8>) -> u64 {
    out.shrink_to_fit();
    let (p, l) = (out.as_mut_ptr() as u64, out.len() as u64);
    std::mem::forget(out);
    (p << 32) | l
}
