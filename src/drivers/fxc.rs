#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use crate::error::{Error, ErrorKind, Result};
use crate::proto::drivers::fxc;
use crate::utilities;

use crate::utilities::{any_as_u8_slice, compute_file_identity, wine_wrap};
use failure::ResultExt;
use filebuffer::FileBuffer;
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::Command;

pub enum InputFormat {
    Hlsl,
}

pub enum OutputFormat {
    Dxbc,
}

lazy_static! {
    pub static ref FXC_PATH: String = env::var("FXC_PATH")
        .expect("FXC_PATH must be set")
        .to_string();
}

lazy_static! {
    pub static ref FXC_IDENTITY: String =
        { compute_file_identity(Path::new(&*FXC_PATH)).expect("failed to calculate FXC identity") };
}

lazy_static! {
    pub static ref FXC_ENABLED: bool = { env::var("FXC_PATH").is_ok() };
}

pub fn help() -> Result<String> {
    let (command, mut args) = wine_wrap(FXC_PATH.to_string());

    let mut output = Command::new(command);
    args.push("-help".to_string());
    for arg in &args {
        output.arg(arg);
    }

    let output = output.output();
    match output {
        Ok(ref output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.to_string())
        }
        Err(err) => Err(Error::bug(format!(
            "failed to run command - details: {:?}",
            err
        ))),
    }
}

pub fn compile() -> Result<String> {
    let (command, mut args) = wine_wrap(FXC_PATH.to_string());

    let mut output = Command::new(command);
    args.push("-help".to_string());
    for arg in &args {
        output.arg(arg);
    }

    let output = output.output();
    match output {
        Ok(ref output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let _stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() {
                Ok(stdout.to_string())
            } else {
                Err(Error::process(format!(
                    "failed to run command - details: {:?}",
                    stdout.to_string()
                )))
            }
        }
        Err(err) => Err(Error::bug(format!(
            "failed to run command - details: {:?}",
            err
        ))),
    }
}

pub fn identity_from_request(source_identity: &str, options: &fxc::CompileOptions) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::default();
    hasher.input(&*FXC_IDENTITY.as_bytes());
    hasher.input(&source_identity.as_bytes());
    hasher.input(&options.entry_point.as_bytes());
    /*options.definitions.iter().for_each(|(name, value)| {
        hasher.input(&name.as_bytes());
        hasher.input(&value.as_bytes());
    });
    hasher.input(&unsafe { any_as_u8_slice(&options.input_format) });
    hasher.input(&unsafe { any_as_u8_slice(&options.output_format) });
    hasher.input(&unsafe { any_as_u8_slice(&options.target_version) });
    hasher.input(&unsafe { any_as_u8_slice(&options.target_profile) });
    hasher.input(&unsafe { any_as_u8_slice(&options.optimization_level) });
    hasher.input(&unsafe { any_as_u8_slice(&options.hlsl_version) });
    hasher.input(&unsafe { any_as_u8_slice(&options.warning_level) });
    hasher.input(&unsafe { any_as_u8_slice(&options.validation_level) });
    hasher.input(&unsafe { any_as_u8_slice(&options.code_generation) });
    hasher.input(&unsafe { any_as_u8_slice(&options.debug_info) });
    hasher.input(&unsafe { any_as_u8_slice(&options.listing_info) });
    hasher.input(&unsafe { any_as_u8_slice(&options.flow_control) });
    hasher.input(&unsafe { any_as_u8_slice(&options.denorm) });
    hasher.input(&unsafe { any_as_u8_slice(&options.matrix_packing) });
    hasher.input(&unsafe { any_as_u8_slice(&options.signature_packing) });
    hasher.input(&unsafe { any_as_u8_slice(&options.all_resources_bound) });
    hasher.input(&unsafe { any_as_u8_slice(&options.enable_16bit_types) });
    hasher.input(&unsafe { any_as_u8_slice(&options.legacy_macro_expansion) });
    hasher.input(&unsafe { any_as_u8_slice(&options.color_coded_listing) });
    hasher.input(&unsafe { any_as_u8_slice(&options.strict_mode) });
    hasher.input(&unsafe { any_as_u8_slice(&options.force_ieee) });
    hasher.input(&unsafe { any_as_u8_slice(&options.output_include_depth) });
    hasher.input(&unsafe { any_as_u8_slice(&options.output_include_details) });
    hasher.input(&unsafe { any_as_u8_slice(&options.output_hex_literals) });
    hasher.input(&unsafe { any_as_u8_slice(&options.output_instruction_numbers) });
    hasher.input(&unsafe { any_as_u8_slice(&options.output_instruction_offsets) });
    hasher.input(&unsafe { any_as_u8_slice(&options.output_optimizer_commands) });
    hasher.input(&unsafe { any_as_u8_slice(&options.ignore_line_directives) });
    hasher.input(&unsafe { any_as_u8_slice(&options.deny_legacy_cbuffer_load) });
    if let Some(ref spirv) = options.spirv {
        // Only hash SPIR-V options if that is the output format
        if options.output_format == dxc::OutputFormat::Spirv as i32
            || options.output_format == dxc::OutputFormat::Smolv as i32
        {
            hasher.input(&unsafe { any_as_u8_slice(&spirv.version) });
            hasher.input(&unsafe { any_as_u8_slice(&spirv.emit_reflection) });
            hasher.input(&unsafe { any_as_u8_slice(&spirv.dx_position_w) });
            hasher.input(&unsafe { any_as_u8_slice(&spirv.invert_y) });
            hasher.input(&unsafe { any_as_u8_slice(&spirv.resource_layout) });
            spirv.binding_shifts.iter().for_each(|binding| {
                hasher.input(&unsafe { any_as_u8_slice(&binding.binding_type) });
                hasher.input(&unsafe { any_as_u8_slice(&binding.shift) });
                hasher.input(&unsafe { any_as_u8_slice(&binding.space) });
            });
            spirv.binding_registers.iter().for_each(|binding| {
                hasher.input(&unsafe { any_as_u8_slice(&binding.type_number) });
                hasher.input(&unsafe { any_as_u8_slice(&binding.space) });
                hasher.input(&unsafe { any_as_u8_slice(&binding.binding) });
                hasher.input(&unsafe { any_as_u8_slice(&binding.set) });
            });
            spirv.opt_config.iter().for_each(|value| {
                hasher.input(&value.as_bytes());
            });
            spirv.debug_info.iter().for_each(|value| {
                hasher.input(&value.as_bytes());
            });
            spirv.extensions.iter().for_each(|value| {
                hasher.input(&value.as_bytes());
            });
        }
    }*/
    let data = hasher.result().to_vec();
    let data = smush::encode_data(&data, smush::Encoding::Base58).unwrap();
    String::from_utf8(data).unwrap()
}
