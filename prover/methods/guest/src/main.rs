// Phase 2a spike guest.
//
// This is deliberately not the policy engine. It exists to measure what the
// zkVM costs on this machine for a frame-shaped input, so that Task 2 onward
// can be planned against real numbers rather than guesses. The shape it fixes
// — host writes one length-prefixed frame, guest commits a 32-byte digest —
// is the shape the policy guest will keep.

use risc0_zkvm::guest::env;
use sha2::{Digest, Sha256};

/// Read one length-prefixed frame from the host.
///
/// `risc0_zkvm::guest::env::read_frame` does exactly this, but in 3.0.6 it is
/// marked `#[stability::unstable]` and will not compile without opting the
/// guest into the `unstable` feature — while its host-side counterpart,
/// `ExecutorEnvBuilder::write_frame`, is stable. Rather than put the guest's
/// only input path behind an unstable flag, this reproduces the same two reads
/// on `read_slice`, which is stable. The wire format is unchanged: a
/// little-endian `u32` length followed by that many bytes.
fn read_frame() -> Vec<u8> {
    let mut len: u32 = 0;
    env::read_slice(core::slice::from_mut(&mut len));
    let mut bytes = vec![0u8; len as usize];
    env::read_slice(&mut bytes);
    bytes
}

fn main() {
    let input = read_frame();

    // `sha2` rather than a risc0 precompile crate on purpose: the policy guest
    // must hash exactly the bytes the TypeScript engine hashes, and keeping one
    // crate on both sides is what makes that checkable. See prover/README.md.
    let digest: [u8; 32] = Sha256::digest(&input).into();

    env::commit_slice(&digest);
}
