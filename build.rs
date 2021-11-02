extern crate embed_resource;
use std::{env, fs, path::Path};

fn main() {
    let dir = fs::canonicalize(env::var("CARGO_MANIFEST_DIR").unwrap()).unwrap();
    embed_resource::compile(Path::new(&dir).join("res").join("exe.rc"));
}
