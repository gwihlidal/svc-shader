use crate::utilities::compute_file_identity;
use std::env;
use std::path::Path;

pub enum InputFormat {
    Spirv,
}

pub enum OutputFormat {
    Spirv,
}

lazy_static! {
    pub static ref SPIRV_VAL_PATH: String = env::var("VULKAN_PATH")
        .expect("VULKAN_PATH must be set")
        .to_string()
        + "/bin/spirv-val";
}

lazy_static! {
    pub static ref SPIRV_VAL_IDENTITY: String = {
        compute_file_identity(Path::new(&*SPIRV_VAL_PATH))
            .expect("failed to calculate SPIRV_VAL identity")
    };
}

lazy_static! {
    pub static ref SPIRV_VAL_ENABLED: bool = { env::var("SPIRV_VAL_PATH").is_ok() };
}

/*
    ./spirv-val -
*/
