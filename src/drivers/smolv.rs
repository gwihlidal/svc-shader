use crate::utilities::compute_file_identity;
use std::env;
use std::path::Path;

lazy_static! {
    pub static ref SMOLV_PATH: String = env::var("SMOLV_PATH")
        .expect("SMOLV_PATH must be set")
        .to_string();
}

lazy_static! {
    pub static ref SMOLV_IDENTITY: String = {
        compute_file_identity(Path::new(&*SMOLV_PATH)).expect("failed to calculate SMOLV identity")
    };
}

lazy_static! {
    pub static ref SMOLV_ENABLED: bool = { env::var("SMOLV_PATH").is_ok() };
}
