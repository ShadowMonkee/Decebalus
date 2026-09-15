use axum::{response::IntoResponse, Json};
use serde::Serialize;
use crate::services::attacks::{self, docs::ModuleDoc, ModuleMeta};

/// A module as presented on the Modules page: the dispatch metadata plus the
/// human-facing documentation, flattened into a single JSON object.
#[derive(Serialize)]
struct ModuleView {
    #[serde(flatten)]
    meta: ModuleMeta,
    #[serde(flatten)]
    doc: ModuleDoc,
}

/// List all available attack/exploit modules with their metadata and documentation.
/// GET /api/modules
pub async fn list_modules() -> impl IntoResponse {
    let views: Vec<ModuleView> = attacks::all_meta()
        .into_iter()
        .map(|meta| {
            let doc = attacks::docs::module_doc(&meta.job_type);
            ModuleView { meta, doc }
        })
        .collect();

    Json(views)
}
