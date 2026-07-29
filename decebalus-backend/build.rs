// Cargo only re-runs a crate's build when its own .rs files change; `RustEmbed`
// reads the frontend's `dist/` folder at compile time without Cargo knowing that
// folder is a dependency. Without this, `npm run build` regenerating `dist/`
// followed by `cargo build --features embed-ui` could silently reuse a stale
// cached binary with the old UI baked in.
fn main() {
    if std::env::var_os("CARGO_FEATURE_EMBED_UI").is_some() {
        println!("cargo:rerun-if-changed=../decebalus-frontend/dist");
    }
}
