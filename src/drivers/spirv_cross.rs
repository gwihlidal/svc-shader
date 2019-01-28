use crate::utilities::compute_file_identity;
use std::env;
use std::path::Path;

pub enum InputFormat {
    Pssl,
}

pub enum OutputFormat {
    Binary,
}

lazy_static! {
    pub static ref SPIRV_CROSS_PATH: String = env::var("VULKAN_PATH")
        .expect("VULKAN_PATH must be set")
        .to_string()
        + "/bin/spirv-cross";
}

lazy_static! {
    pub static ref SPIRV_CROSS_IDENTITY: String = {
        compute_file_identity(Path::new(&*SPIRV_CROSS_PATH))
            .expect("failed to calculate SPIRV_CROSS identity")
    };
}

lazy_static! {
    pub static ref SPIRV_CROSS_ENABLED: bool = { env::var("SPIRV_CROSS_PATH").is_ok() };
}

/*
    Usage: spirv-cross
        [--output <output path>]
        [SPIR-V file]
        [--es]
        [--no-es]
        [--version <GLSL version>]
        [--dump-resources]
        [--help]
        [--force-temporary]
        [--vulkan-semantics]
        [--flatten-ubo]
        [--fixup-clipspace]
        [--flip-vert-y]
        [--iterations iter]
        [--cpp]
        [--cpp-interface-name <name>]
        [--msl]
        [--msl-version <MMmmpp>]
        [--msl-swizzle-texture-samples]
        [--msl-ios]
        [--hlsl]
        [--reflect]
        [--shader-model]
        [--hlsl-enable-compat]
        [--separate-shader-objects]
        [--pls-in format input-name]
        [--pls-out format output-name]
        [--remap source_name target_name components]
        [--extension ext]
        [--entry name]
        [--stage <stage (vert, frag, geom, tesc, tese comp)>]
        [--remove-unused-variables]
        [--flatten-multidimensional-arrays]
        [--no-420pack-extension]
        [--remap-variable-type <variable_name> <new_variable_type>]
        [--rename-interface-variable <in|out> <location> <new_variable_name>]
        [--set-hlsl-vertex-input-semantic <location> <semantic>]
        [--rename-entry-point <old> <new> <stage>]
        [--combined-samplers-inherit-bindings]
        [--no-support-nonzero-baseinstance]
*/
