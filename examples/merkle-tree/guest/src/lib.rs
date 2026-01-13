#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::ops::Deref;

/// Computes the Merkle root of a 4-leaf tree
///
/// Tree structure:
///        root
///       /    \
///     h01    h23
///    /  \   /  \
///   h0  h1 h2  h3
///   |   |  |   |
///  l1  l2  l3  l4
#[jolt::provable(memory_size = 32768, max_trace_length = 65536)]
fn merkle_tree(
    leaf1: &[u8],
    leaf2: jolt::TrustedAdvice<[u8; 32]>,
    leaf3: jolt::TrustedAdvice<[u8; 32]>,
    leaf4: jolt::UntrustedAdvice<[u8; 32]>,
) -> [u8; 32] {
    let h0 = jolt_inlines_sha2::Sha256::digest(leaf1);
    let h1 = jolt_inlines_sha2::Sha256::digest(leaf2.deref());
    let h2 = jolt_inlines_sha2::Sha256::digest(leaf3.deref());
    let h3 = jolt_inlines_sha2::Sha256::digest(leaf4.deref());

    let mut pair_01 = [0u8; 64];
    pair_01[..32].copy_from_slice(&h0);
    pair_01[32..].copy_from_slice(&h1);
    let h01 = jolt_inlines_sha2::Sha256::digest(&pair_01);

    let mut pair_23 = [0u8; 64];
    pair_23[..32].copy_from_slice(&h2);
    pair_23[32..].copy_from_slice(&h3);
    let h23 = jolt_inlines_sha2::Sha256::digest(&pair_23);

    let mut root_pair = [0u8; 64];
    root_pair[..32].copy_from_slice(&h01);
    root_pair[32..].copy_from_slice(&h23);
    jolt_inlines_sha2::Sha256::digest(&root_pair)
}

#[jolt::provable(
    memory_size = 1048576,
    max_trace_length = 33554432,
    max_untrusted_advice_size = 262144
)]
fn merkle_tree_4096(leaves: jolt::UntrustedAdvice<Vec<[u8; 32]>>) -> [u8; 32] {
    let leaves = leaves.deref();
    if leaves.len() != 4096 {
        return [0u8; 32];
    }

    let mut level = Vec::with_capacity(leaves.len());
    for leaf in leaves.iter() {
        level.push(jolt_inlines_sha2::Sha256::digest(leaf));
    }

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len() / 2);
        let mut i = 0;
        while i < level.len() {
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&level[i]);
            pair[32..].copy_from_slice(&level[i + 1]);
            next_level.push(jolt_inlines_sha2::Sha256::digest(&pair));
            i += 2;
        }
        level = next_level;
    }

    level[0]
}
