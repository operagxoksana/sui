// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::{exit, Command, ExitStatus};

fn main() -> Result<(), ExitStatus> {
    println!("cargo:rerun-if-changed=build.rs");

    let bridge_path = "../../bridge/evm";
    let bridge_lib_path = "../../bridge/evm/lib";

    // Check if Forge is installed
    let forge_installed = Command::new("which")
        .arg("forge")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    eprintln!("Forge installed!");
    if !forge_installed {
        eprintln!("Installing forge");
        let output = Command::new("curl")
            .arg("-L")
            .arg("https://foundry.paradigm.xyz")
            .output()
            .expect("Failed to download Forge");

        if !output.status.success() {
            eprintln!("Error downloading Forge: {:?}", output);
            exit(1);
        }
    }

    // check if dependencies are installed
    if is_directory_empty(bridge_lib_path) {
        // Run Foundry CLI command to install dependencies
        Command::new("forge")
            .current_dir(bridge_path)
            .arg("install")
            .arg("https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable@v5.0.1")
            .arg("https://github.com/foundry-rs/forge-std@v1.3.0")
            .arg("https://github.com/OpenZeppelin/openzeppelin-foundry-upgrades")
            .arg("--no-git")
            .arg("--no-commit")
            .status()
            .expect("Failed to execute Foundry CLI command");
    }

    Ok(())
}

fn is_directory_empty(dir_path: &str) -> bool {
    if let Ok(entries) = fs::read_dir(dir_path) {
        return entries.count() == 0;
    }
    false
}