# defender

Microsoft Defender, for forensics: its detection history (`ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<n>\<GUID>`), one file per detection, read into the threat, where it was found, who and what was involved, and when. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-defender = "0.1"
```

```rust
let detection = defender::read(&std::fs::read("DetectionHistory/02/6AFE33A0-19BA-4FFF-892F-B700539D7D63")?)?;
for resource in &detection.resources {
    println!("{:?} in {} {}", detection.threat_name, resource.kind, resource.location);
}
```

## What you get

- `detect(head)`: whether a file is a detection history file (`Magic.Version:1.2` at offset 0x30).
- `read(data)`: the detection's identifier, the threat's name and category (`category_name()`: `VIRUS`, `RANSOM`, …), the user and process involved, when it was first detected, remediated and last changed (UTC), and each resource it was found in (`file`, `containerfile`, `webfile` with its URL, `process`, `regkey`, …) with its tracking data: start time, SHA-256, SHA-1, MD5, size, threat identifier, scan source. `start_time()` and `sha256()` read them as plaso does.
- Damage goes to `problems`, never a panic.

## How it's checked

- plaso's detection history files (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every detection plaso reads from them with its `windefender_history` parser, read the same: file, time, threat, user, process, SHA-256, container and web files (`tests/oracle/`). Beyond plaso: identifiers, categories, the three other times and every tracking value.
- Property tests: arbitrary and damaged files give a detection, problems or an error, never a panic.

The format, as libyal's dtformats documents it: typed values (size, type, data, padded to 8 bytes) in sets separated by `Magic.Version:1.2`.

## Licence

MIT or Apache-2.0, at your option.
