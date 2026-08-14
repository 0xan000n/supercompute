// Reading resolved crate versions out of a `Cargo.lock`.
//
// `include!`d by `build.rs` (a build script cannot be a library) and by
// `tests/lock_pins.rs`, so the rules below are exercised by `cargo test`
// instead of only by whether a build happened to succeed.
//
// Hand-rolled rather than a `toml` build-dependency: the shape being read is
// three lines of a generated file, and a parser dependency here is one more
// thing that has to be pinned in order to pin anything.

/// The resolved version of `name`, or `None` if the lock does not mention it.
///
/// Two copies of one crate in a single lock is a panic wherever it is found:
/// that is exactly the situation a pin is supposed to make visible, so it is
/// said out loud rather than resolved by picking one.
pub fn optional_locked_version(lock: &str, name: &str) -> Option<String> {
    let needle = format!("name = \"{name}\"");
    let mut versions: Vec<String> = Vec::new();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line.trim() != needle {
            continue;
        }
        let version = lines
            .next()
            .and_then(|l| l.trim().strip_prefix("version = \""))
            .and_then(|l| l.strip_suffix('"'))
            .unwrap_or_else(|| panic!("no version line after {needle} in Cargo.lock"));
        versions.push(version.to_owned());
    }
    match versions.len() {
        0 => None,
        1 => versions.pop(),
        _ => panic!(
            "{name} appears {} times in one Cargo.lock: {versions:?}",
            versions.len()
        ),
    }
}

/// The same, but an absent crate is a build failure. Writing `"unknown"` into a
/// manifest whose entire job is to be precise would be worse than not building.
pub fn locked_version(lock: &str, name: &str) -> String {
    optional_locked_version(lock, name).unwrap_or_else(|| panic!("{name} is not in Cargo.lock"))
}

/// The version the **guest's** lock pins — the one that ends up in the image —
/// plus a loud complaint if the prover workspace's lock disagrees.
///
/// `prover/methods/guest` is its own cargo workspace with its own committed
/// lock, and that lock is what the guest compiler resolves against. The ImageID
/// is the real pin, so drift between the two locks does not mean the emitted
/// manifest describes the wrong image — the guest lock is authoritative and is
/// what gets recorded. It means the repository is holding two answers to the
/// same question, which is a thing nobody should discover by reading a
/// `release.json` and wondering which number to believe.
pub fn guest_pinned_version(guest_lock: &str, host_lock: &str, name: &str) -> String {
    let guest = locked_version(guest_lock, name);
    if let Some(host) = optional_locked_version(host_lock, name) {
        assert!(
            host == guest,
            "{name} is locked at {guest} in prover/methods/guest/Cargo.lock (the lock that \
             governs what is compiled into the image) but at {host} in prover/Cargo.lock. \
             release.json would record {guest} while the host-side differential tests run \
             against {host}. Reconcile the two locks."
        );
    }
    guest
}
