//! Building `prover/release.json`.
//!
//! The manifest's *shape* lives in the `release-manifest` crate, because the
//! verifier reads it and the verifier may not depend on this crate (depending on
//! `host` would mean building the guest to check a receipt). What lives here is
//! the part only the prover knows: the ImageID it measured, the policy identity its
//! build scripts derived, and the toolchain `build.rs` recorded while compiling
//! this binary.
//!
//! Everything except `builtAt` is a compile-time constant. There is no runtime
//! input to `--emit-release`, so two runs of the same binary differ in exactly
//! one field.

use std::time::{SystemTime, UNIX_EPOCH};

use methods::{POLICY_ID_V2, RULES_DIGEST};
use release_manifest::{ReleaseManifest, ToolchainPins, JOURNAL_VERSION, RECEIPT_CODEC_BINCODE_V1};

/// The toolchain pins `build.rs` read out of the build environment.
pub mod toolchain {
    include!(concat!(env!("OUT_DIR"), "/toolchain.rs"));
}

/// The manifest for the image this binary was built against.
pub fn release_manifest(built_at: String) -> ReleaseManifest {
    ReleaseManifest {
        image_id_hex: crate::image_id_hex(),
        policy_id: POLICY_ID_V2.to_owned(),
        rules_digest: RULES_DIGEST.to_owned(),
        journal_version: JOURNAL_VERSION,
        risc0_version: risc0_zkvm::VERSION.to_owned(),
        // The codec the daemon already ships: `GET /jobs/:id` base64s
        // `bincode::serialize(&receipt)` and `tests/api.rs` round-trips it.
        // Claiming it here is describing what happens, not choosing it.
        receipt_codec: RECEIPT_CODEC_BINCODE_V1.to_owned(),
        built_at,
        toolchain: ToolchainPins {
            host_rustc: toolchain::HOST_RUSTC.to_owned(),
            guest_rustc: toolchain::GUEST_RUSTC.to_owned(),
            rzup_rust_toolchain: toolchain::RZUP_RUST_TOOLCHAIN.to_owned(),
            risc0_build_crate: toolchain::RISC0_BUILD_CRATE.to_owned(),
            unicode_normalization_crate: toolchain::UNICODE_NORMALIZATION_CRATE.to_owned(),
            unicode_properties_crate: toolchain::UNICODE_PROPERTIES_CRATE.to_owned(),
        },
    }
}

/// `now` as RFC 3339 UTC, seconds resolution: `2026-08-14T09:07:00Z`.
///
/// Hand-rolled rather than a `chrono`/`time` dependency. The host's dependency
/// list is a thing auditors read, and one field of one generated file is not
/// worth a date library — the calendar arithmetic below is Howard Hinnant's
/// `civil_from_days`, which is exact for every day this program will ever see
/// and is unit-tested against known dates.
pub fn rfc3339_utc(now: SystemTime) -> String {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is before 1970")
        .as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> String {
        rfc3339_utc(UNIX_EPOCH + Duration::from_secs(secs))
    }

    /// Fixed vectors, each checkable with `date -u -r <secs>`.
    #[test]
    fn timestamps_are_rfc3339_utc() {
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(1), "1970-01-01T00:00:01Z");
        // 2000-02-29, the leap day the century rule keeps.
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        // 2100-02-28 is followed by 2100-03-01: not a leap year.
        assert_eq!(at(4_107_456_000), "2100-02-28T00:00:00Z");
        assert_eq!(at(4_107_542_400), "2100-03-01T00:00:00Z");
        assert_eq!(at(1_767_225_599), "2025-12-31T23:59:59Z");
        assert_eq!(at(1_767_225_600), "2026-01-01T00:00:00Z");
    }

    /// The manifest the emitter produces is the one the verifier's type accepts,
    /// including `deny_unknown_fields` in both directions.
    #[test]
    fn the_emitted_manifest_round_trips_through_the_verifier_type() {
        let manifest = release_manifest("2026-01-01T00:00:00Z".to_owned());
        let json = serde_json::to_string_pretty(&manifest).expect("serializes");
        let back: release_manifest::ReleaseManifest =
            serde_json::from_str(&json).expect("the verifier can read what the host emits");
        assert_eq!(back, manifest);

        // The three identities are the ones the rest of the crate already uses,
        // not a second derivation.
        assert_eq!(manifest.image_id_hex, crate::image_id_hex());
        assert_eq!(manifest.policy_id, methods::POLICY_ID_V2);
        assert_eq!(manifest.rules_digest, methods::RULES_DIGEST);
        assert_eq!(manifest.risc0_version, risc0_zkvm::VERSION);
    }

    /// A pin that says "unavailable" is a pin that pins nothing. This is the
    /// test that fails if `build.rs` stops being able to find a toolchain.
    #[test]
    fn every_toolchain_pin_has_a_value() {
        for (name, value) in [
            ("hostRustc", toolchain::HOST_RUSTC),
            ("guestRustc", toolchain::GUEST_RUSTC),
            ("rzupRustToolchain", toolchain::RZUP_RUST_TOOLCHAIN),
            ("risc0BuildCrate", toolchain::RISC0_BUILD_CRATE),
            (
                "unicodeNormalizationCrate",
                toolchain::UNICODE_NORMALIZATION_CRATE,
            ),
            (
                "unicodePropertiesCrate",
                toolchain::UNICODE_PROPERTIES_CRATE,
            ),
        ] {
            assert!(!value.is_empty(), "{name} is empty");
            assert_ne!(value, "unavailable", "{name} could not be determined");
        }
    }
}
