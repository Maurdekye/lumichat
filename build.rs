use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=front/src/*");
    let status = Command::new("trunk")
        .args(["build", "--release"])
        .current_dir("./front")
        .status()
        .unwrap();

    assert!(status.success(), "Frontend build failed");
}
