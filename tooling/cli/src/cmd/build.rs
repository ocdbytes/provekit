use {
    super::HashFunction,
    anyhow::{Context, Result},
    std::{env, fs, os::unix::process::CommandExt, path::PathBuf, process::Command},
    tracing::{info, warn},
};

/// Path to the file that tracks the last built hash function
fn hash_tracking_file() -> Result<PathBuf> {
    let target_dir = if let Ok(dir) = env::var("CARGO_TARGET_DIR") {
        PathBuf::from(dir)
    } else {
        // Default to workspace root/target if CARGO_TARGET_DIR is not set
        let workspace_root = find_workspace_root()?;
        workspace_root.join("target")
    };
    fs::create_dir_all(&target_dir).context("Failed to create target directory")?;
    Ok(target_dir.join(".provekit_hash"))
}

/// Find the workspace root by looking for Cargo.toml
fn find_workspace_root() -> Result<PathBuf> {
    let mut current = env::current_dir()?;
    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            // Check if it's a workspace
            let contents = fs::read_to_string(&cargo_toml)?;
            if contents.contains("[workspace]") {
                return Ok(current);
            }
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => anyhow::bail!("Could not find workspace root"),
        }
    }
}

/// Get the last built hash function, if any
fn get_last_built_hash() -> Result<Option<HashFunction>> {
    let tracking_file = hash_tracking_file()?;
    if !tracking_file.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(&tracking_file).context("Failed to read hash tracking file")?;
    let hash_str = content.trim();
    match hash_str {
        "skyscraper" => Ok(Some(HashFunction::Skyscraper)),
        "sha2" => Ok(Some(HashFunction::Sha2)),
        "blake3" => Ok(Some(HashFunction::Blake3)),
        _ => {
            warn!("Unknown hash function in tracking file: {}", hash_str);
            Ok(None)
        }
    }
}

/// Save the last built hash function
fn save_last_built_hash(hash: HashFunction) -> Result<()> {
    let tracking_file = hash_tracking_file()?;
    let hash_str = match hash {
        HashFunction::Skyscraper => "skyscraper",
        HashFunction::Sha2 => "sha2",
        HashFunction::Blake3 => "blake3",
    };
    fs::write(&tracking_file, hash_str).context("Failed to write hash tracking file")?;

    Ok(())
}

/// Check if a rebuild is necessary
fn needs_rebuild(requested_hash: HashFunction) -> Result<bool> {
    let last_hash = get_last_built_hash()?;

    match last_hash {
        Some(last) => Ok(last != requested_hash),
        None => Ok(true), // No previous build tracked, need to build
    }
}

/// Build the workspace with the specified hash function
fn build_with_hash(hash: HashFunction) -> Result<()> {
    let feature_flag = hash.feature_flag();
    info!(
        "Building workspace with hash function: {} (feature: {})",
        match hash {
            HashFunction::Skyscraper => "skyscraper",
            HashFunction::Sha2 => "SHA2",
            HashFunction::Blake3 => "BLAKE3",
        },
        feature_flag
    );

    let workspace_root = find_workspace_root()?;

    // Build the CLI with the selected hash feature for provekit-common
    // The feature syntax is: package/feature
    // This will build all dependencies with the same feature enabled
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root);

    // Detect if we should build in release mode based on current binary
    let is_release = if let Ok(current_exe) = env::current_exe() {
        current_exe.to_string_lossy().contains("/release/")
    } else {
        false
    };

    // Use the feature syntax: provekit-common/hash-xxx
    let feature_arg = format!("provekit-common/{}", feature_flag);
    let mut args = vec![
        "build",
        "--package",
        "provekit-cli",
        "--features",
        &feature_arg,
    ];

    if is_release {
        args.push("--release");
    }

    cmd.args(&args);

    // Forward cargo environment variables
    cmd.envs(env::vars());

    let status = cmd.status().context("Failed to execute cargo build")?;

    if !status.success() {
        anyhow::bail!("Cargo build failed");
    }

    // Save the hash function we just built with
    save_last_built_hash(hash)?;

    info!(
        "Build completed successfully with hash function: {}",
        match hash {
            HashFunction::Skyscraper => "skyscraper",
            HashFunction::Sha2 => "SHA2",
            HashFunction::Blake3 => "BLAKE3",
        }
    );

    Ok(())
}

/// Get the path to the built CLI binary
fn get_cli_binary_path() -> Result<PathBuf> {
    let workspace_root = find_workspace_root()?;

    // Try to detect the profile from the current binary's path
    // or default to debug
    let profile = if let Ok(current_exe) = env::current_exe() {
        if current_exe.to_string_lossy().contains("/release/") {
            "release"
        } else {
            "debug"
        }
    } else {
        "debug"
    };

    let target_dir = env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("target"));

    Ok(target_dir.join(profile).join("provekit-cli"))
}

/// Ensure the workspace is built with the specified hash function
/// Returns true if a rebuild was performed (and re-execution might be needed)
pub fn ensure_built_with_hash(hash: HashFunction) -> Result<bool> {
    if needs_rebuild(hash)? {
        info!("Rebuild necessary: hash function changed or no previous build tracked");
        build_with_hash(hash)?;
        Ok(true)
    } else {
        info!("No rebuild necessary: hash function matches last build");
        Ok(false)
    }
}

/// Re-execute the current command with the newly built binary
/// This should be called after a rebuild to ensure the command runs with the
/// correct hash function
pub fn re_execute_with_new_binary() -> Result<()> {
    let binary_path = get_cli_binary_path()?;

    if !binary_path.exists() {
        anyhow::bail!("Built binary not found at: {}", binary_path.display());
    }

    info!(
        "Re-executing with newly built binary: {}",
        binary_path.display()
    );

    // Get the current command line arguments
    let args: Vec<String> = env::args().skip(1).collect();

    // Re-execute with the new binary
    // This replaces the current process
    let err = Command::new(&binary_path)
        .args(&args)
        .envs(env::vars())
        .exec();

    // exec only returns on error
    Err(err.into())
}
