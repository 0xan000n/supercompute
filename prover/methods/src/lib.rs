//! The compiled guest: its ELF, its ImageID, and the policy identity baked into
//! it. All three are generated at build time — see `build.rs`.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
include!(concat!(env!("OUT_DIR"), "/policy_consts.rs"));
