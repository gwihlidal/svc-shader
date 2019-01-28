use crate::error::{Error, ErrorKind, Result};
use crate::proto::drivers::spirv_dis;
use crate::utilities::{any_as_u8_slice, compute_file_identity, wine_wrap, TempFile};
use failure::ResultExt;
use filebuffer::FileBuffer;
use std::env;
use std::path::Path;
use std::process::Command;

lazy_static! {
    pub static ref VULKAN_PATH: String = env::var("VULKAN_PATH")
        .expect("VULKAN_PATH must be set")
        .to_string();
    pub static ref SPIRV_DIS_PATH: String = Path::new(&*VULKAN_PATH)
        .join("spirv-dis")
        .to_string_lossy()
        .to_string();
}

lazy_static! {
    pub static ref SPIRV_DIS_IDENTITY: String = {
        compute_file_identity(&Path::new(&*SPIRV_DIS_PATH))
            .expect("failed to calculate SPIRV_DIS identity")
    };
}

lazy_static! {
    pub static ref VULKAN_ENABLED: bool = { env::var("VULKAN_PATH").is_ok() };
}

pub fn disassemble(
    input_path: &Path,
    options: &spirv_dis::DisassembleOptions,
    temp_path: &Path,
) -> Result<(Vec<u8>, String)> {
    let input_path = input_path.to_string_lossy();

    let output_handle = TempFile::new(&temp_path);
    let output_path = &output_handle.path();

    let (command, mut args) = wine_wrap(SPIRV_DIS_PATH.to_string());

    if options.colorize {
        args.push("--color".to_string());
    } else {
        args.push("--no-color".to_string());
    }

    if options.no_indent {
        args.push("--no-indent".to_string());
    }

    if options.no_header {
        args.push("--no-header".to_string());
    }

    if options.raw_id {
        args.push("--raw-id".to_string());
    }

    if options.offsets {
        args.push("--offsets".to_string());
    }

    args.push("-o".to_string());
    args.push(output_path.to_string_lossy().to_string());

    args.push(input_path.to_string());

    let mut output = Command::new(command);
    for arg in &args {
        output.arg(arg);
    }

    let output = output.output();
    match output {
        Ok(ref output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() {
                let output_buffer = FileBuffer::open(&output_path)
                    .with_context(|_| ErrorKind::path(&output_path))?;
                let result = output_buffer.to_vec();
                Ok((result, stdout.to_string()))
            } else {
                Err(Error::process(format!(
                    "failed to run command - details: {:?} - {:?}",
                    stdout.to_string(),
                    stderr.to_string()
                )))
            }
        }
        Err(err) => Err(Error::bug(format!(
            "failed to run command: {:?} - details: {:?}",
            args, err
        ))),
    }
}

pub fn identity_from_request(
    input_identity: &str,
    options: &spirv_dis::DisassembleOptions,
) -> String {
    use base58::ToBase58;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::default();
    hasher.input(&*SPIRV_DIS_IDENTITY.as_bytes());
    hasher.input(&input_identity.as_bytes());
    hasher.input(&unsafe { any_as_u8_slice(&options.colorize) });
    hasher.input(&unsafe { any_as_u8_slice(&options.no_indent) });
    hasher.input(&unsafe { any_as_u8_slice(&options.no_header) });
    hasher.input(&unsafe { any_as_u8_slice(&options.raw_id) });
    hasher.input(&unsafe { any_as_u8_slice(&options.offsets) });
    hasher.result().to_vec().to_base58()
}

/*
  /app/vulkan/spirv-dis - Disassemble a SPIR-V binary module

  Usage: /app/vulkan/spirv-dis [options] [<filename>]

  The SPIR-V binary is read from <filename>. If no file is specified,
  or if the filename is "-", then the binary is read from standard input.

  Options:

  -h, --help      Print this help.
  --version       Display disassembler version information.

  -o <filename>   Set the output filename.
                  Output goes to standard output if this option is
                  not specified, or if the filename is "-".

  --color         Force color output.  The default when printing to a terminal.
                  Overrides a previous --no-color option.
  --no-color      Don't print in color.  Overrides a previous --color option.
                  The default when output goes to something other than a
                  terminal (e.g. a file, a pipe, or a shell redirection).

  --no-indent     Don't indent instructions.

  --no-header     Don't output the header as leading comments.

  --raw-id        Show raw Id values instead of friendly names.

  --offsets       Show byte offsets for each instruction.
*/
