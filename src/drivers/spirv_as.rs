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
    pub static ref SPIRV_AS_PATH: String = env::var("VULKAN_PATH")
        .expect("VULKAN_PATH must be set")
        .to_string()
        + "/bin/spirv-as";
}

lazy_static! {
    pub static ref SPIRV_AS_IDENTITY: String = {
        compute_file_identity(Path::new(&*SPIRV_AS_PATH))
            .expect("failed to calculate SPIRV_AS identity")
    };
}

lazy_static! {
    pub static ref SPIRV_AS_ENABLED: bool = { env::var("SPIRV_AS_PATH").is_ok() };
}

/*
    ./spirv-as - Create a SPIR-V binary module from SPIR-V assembly text

    Usage: ./spirv-as [options] [<filename>]

    The SPIR-V assembly text is read from <filename>.  If no file is specified,
    or if the filename is "-", then the assembly text is read from standard input.
    The SPIR-V binary module is written to file "out.spv", unless the -o option
    is used.

    Options:

    -h, --help      Print this help.

    -o <filename>   Set the output filename. Use '-' to mean stdout.
    --version       Display assembler version information.
    --preserve-numeric-ids
                    Numeric IDs in the binary will have the same values as in the
                    source. Non-numeric IDs are allocated by filling in the gaps,
                    starting with 1 and going up.
    --target-env {vulkan1.0|vulkan1.1|spv1.0|spv1.1|spv1.2|spv1.3}
                    Use Vulkan 1.0, Vulkan 1.1, SPIR-V 1.0, SPIR-V 1.1,
                    SPIR-V 1.2, or SPIR-V 1.3
*/
