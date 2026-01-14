use jolt_sdk::UntrustedAdvice;
use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt::init();

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_merkle_tree_pow2(target_dir);

    let shared_preprocessing = guest::preprocess_shared_merkle_tree_pow2(&mut program);
    let prover_preprocessing =
        guest::preprocess_prover_merkle_tree_pow2(shared_preprocessing.clone());
    let verifier_preprocessing = guest::preprocess_verifier_merkle_tree_pow2(
        shared_preprocessing,
        prover_preprocessing.generators.to_verifier_setup(),
    );

    let prove_merkle_tree =
        guest::build_prover_merkle_tree_pow2(program, prover_preprocessing.clone());
    let verify_merkle_tree = guest::build_verifier_merkle_tree_pow2(verifier_preprocessing);

    let mut leaves = Vec::with_capacity(256);
    for i in 0..256 {
        leaves.push([i as u8; 32]);
    }

    let now = Instant::now();
    let (output, proof, program_io) = prove_merkle_tree(UntrustedAdvice::new(leaves));
    info!("Prover runtime: {} s", now.elapsed().as_secs_f64());

    let is_valid = verify_merkle_tree(output, program_io.panic, proof);

    info!("output: {}", hex::encode(output));
    info!("valid: {is_valid}");
}
