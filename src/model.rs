use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct CasbinRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub _key: Option<String>,
    pub ptype: String,
    pub v0: String,
    pub v1: String,
    pub v2: String,
    pub v3: String,
    pub v4: String,
    pub v5: String,
}
