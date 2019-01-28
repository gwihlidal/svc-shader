#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use crate::error::{Error, ErrorKind, Result};
use crate::proto::drivers::spirv_dis;
use crate::utilities::{any_as_u8_slice, compute_file_identity, wine_wrap, TempFile};
use failure::ResultExt;
use filebuffer::FileBuffer;
use std::env;
use std::path::Path;
use std::process::Command;

pub enum InputFormat {
    Hlsl,
    Glsl,
    Spirv,
}

pub enum OutputFormat {
    Text,
}

lazy_static! {
    pub static ref RGA_WIN_PATH: String = env::var("RGA_WIN_PATH")
        .expect("RGA_WIN_PATH must be set")
        .to_string();
}

lazy_static! {
    pub static ref RGA_NIX_PATH: String = env::var("RGA_NIX_PATH")
        .expect("RGA_NIX_PATH must be set")
        .to_string();
}

lazy_static! {
    pub static ref RGA_WIN_IDENTITY: String = {
        compute_file_identity(Path::new(&*RGA_WIN_PATH))
            .expect("failed to calculate RGA_WIN identity")
    };
}

lazy_static! {
    pub static ref RGA_NIX_IDENTITY: String = {
        compute_file_identity(Path::new(&*RGA_NIX_PATH))
            .expect("failed to calculate RGA_NIX identity")
    };
}

lazy_static! {
    pub static ref RGA_WIN_ENABLED: bool = { env::var("RGA_WIN_PATH").is_ok() };
}

lazy_static! {
    pub static ref RGA_NIX_ENABLED: bool = { env::var("RGA_NIX_PATH").is_ok() };
}

/*
pub fn disassemble(
    input_path: &Path,
    options: &spirv_dis::DisassembleOptions,
) -> Result<(Vec<u8>, String)> {
    let input_path = input_path.to_string_lossy();

    let output_handle = TempFile::new();
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
*/

/*
    Radeon GPU Analyzer Version: 2.0.1305.268
    Radeon GPU Analyzer is an analysis tool for OpenCL, DirectX, OpenGL and Vulkan

    To view help for ROCm OpenCL: -h -s rocm-cl
    To view help for legacy OpenCL: -h -s cl
    To view help for OpenGL: -h -s opengl
    To view help for Vulkan (GLSL): -h -s vulkan
    To view help for Vulkan (SPIR-V binary input): -h -s vulkan-spv
    To view help for Vulkan (SPIR-V textual input): -h -s vulkan-spv-txt
    To view help for DirectX: -h -s hlsl
    To view help for AMDIL: -h -s amdil





    root@b2ad3c6b4a29:/app# $WINE_PATH $RGA_WIN_PATH -h -s vulkan-spv

*** Vulkan Instructions & Options ***
=====================================
Usage: rga.exe [options] [optional: spv_input_file]

Notes:
 * The input file(s) must be specified in one of two ways:
   1) A single SPIR-V input file provided as "spv_input_file", or
   2) One or more pipeline stage specific shader files specified by the pipeline stage options (--vert, --tesc, etc.).

Generic options:
  --csv-separator arg      Override to default separator for analysis items.
  -l [ --list-asics ]      List the known GPU codenames, architecture names and
                           variant names.
                           To target a specific GPU, use its codename as the
                           argument to the "-c" command line switch.
  -c [ --asic ] arg        Which ASIC to target.  Repeatable.
  --version                Print version string.
  -h [ --help ]            Produce this help message.
  -a [ --analysis ] arg    Path to output analysis file.
  -b [ --binary ] arg      Path to HSA Code Object binary output file.
  --isa arg                Path to output ISA disassembly file(s).
  --livereg arg            Path to live register analysis output file(s).
  --cfg arg                Path to control flow graph output file(s).
  -s [ --source-kind ] arg Source platform: cl for OpenCL, hlsl for DirectX,
                           opengl for OpenGL, vulkan for Vulkan and amdil for
                           AMDIL.
  --parse-isa              Generate a CSV file with a breakdown of each ISA
                           instruction into opcode, operands. etc.

Optimization Levels:
  --O0                  Disable optimizations
  --O1                  Enable minimal optimizations

Input shader type:
  --vert arg            Full path to vertex shader source file.
  --tesc arg            Full path to tessellation control shader source file.
  --tese arg            Full path to tessellation evaluation shader source
                        file.
  --geom arg            Full path to geometry shader source file.
  --frag arg            Full path to fragment shader source file
  --comp arg            Full path to compute shader source file.

Examples:
  Compile vertex & fragment shaders for all supported devicesl; extract ISA, AMD IL and statistics:
    rga.exe -s vulkan-spv --isa output/isa.txt --il output/il.txt -a output/stats.csv --vert source/myVertexShader.spv --frag source/myFragmentShader.spv
  Compile vertex & fragment shaders for Iceland and Fiji; extract ISA, AMD IL and statistics:
    rga.exe -s vulkan-spv -c Iceland -c Fiji --isa output/isa.txt --il output/il.amdil -a output/.csv --vert source/myVertexShader.spv --frag source/myFragmentShader.spv
  Compile vertex shader for Radeon R9 390; extract ISA and binaries:
    rga.exe -s vulkan-spv -c "R9 390" --isa output/isa.txt -b output/binary.bin -a output/stats.csv --vert c:\source\myVertexShader.spv
  Extract ISA for a single SPIR-V file for Baffin, without specifying the pipeline stages:
    rga.exe -s vulkan-spv -c Baffin --isa output/program_isa.txt source/program.spv



root@b2ad3c6b4a29:/app# $WINE_PATH $RGA_WIN_PATH -h -s hlsl

*** DX Instructions & Options (Windows Only) ***
================================================
Usage: rga.exe [options] source_file
Generic options:
  --csv-separator arg      Override to default separator for analysis items.
  -l [ --list-asics ]      List the known GPU codenames, architecture names and
                           variant names.
                           To target a specific GPU, use its codename as the
                           argument to the "-c" command line switch.
  -c [ --asic ] arg        Which ASIC to target.  Repeatable.
  --version                Print version string.
  -h [ --help ]            Produce this help message.
  -a [ --analysis ] arg    Path to output analysis file.
  -b [ --binary ] arg      Path to HSA Code Object binary output file.
  --isa arg                Path to output ISA disassembly file(s).
  --livereg arg            Path to live register analysis output file(s).
  --cfg arg                Path to control flow graph output file(s).
  -s [ --source-kind ] arg Source platform: cl for OpenCL, hlsl for DirectX,
                           opengl for OpenGL, vulkan for Vulkan and amdil for
                           AMDIL.
  --parse-isa              Generate a CSV file with a breakdown of each ISA
                           instruction into opcode, operands. etc.

  --il arg              Path to output IL file(s).

Macro and Include paths Options:
  -D [ --define ] arg      Define symbol or symbol=value. Applicable only to CL
                           and DX files. Repeatable.
  -I [ --IncludePath ] arg Additional include path required for compilation.
                           Repeatable.

DirectX Shader Analyzer options:
  -f [ --function ] arg    D3D shader to compile, DX ASM shader.
  -p [ --profile ] arg     Profile to use for compilation.  REQUIRED.
                           For example: vs_5_0, ps_5_0, etc.
  --DXFlags arg            Flags to pass to D3DCompile.
  --DXLocation arg         Location to the D3DCompiler Dll required for
                           compilation. If none is specified, the default D3D
                           compiler that is bundled with the Analyzer will be
                           used.
  --FXC arg                FXC Command Line. Use full path and specify all
                           arguments in "". For example:
                              rga.exe  -f VsMain1 -s DXAsm -p vs_5_0
                           <Path>\vsBlob.obj  --isa <Path>\vsTest.isa --FXC
                           "<Path>\fxc.exe /E VsMain1 /T vs_5_0 /Fo
                           <Path>\vsBlob.obj <Path>\vsTest.fx"
                               In order to use it, DXAsm must be specified. /Fo
                           switch must be used and output file must be the same
                           as the input file for rga.
  --DumpMSIntermediate arg Location to save the MS Blob as text.
  --intrinsics             Enable AMD D3D11 Shader Intrinsics extension.
  --adapters               List all of the supported display adapters that are
                           installed on the system.
                           This is only relevant if you have multiple display
                           adapters installed on your system, and you would
                           like RGA to use the driver which is associated with
                           a non-primary display adapter.By default RGA will
                           use the driver that is associated with the primary
                           display adapter.
  --set-adapter arg        Specify the id of the display adapter whose driver
                           you would like RGA to use.
                           This is only relevant if you have multiple display
                           adapters installed on your system, and you would
                           like RGA to use the driver which is associated with
                           a non-primary display adapter.By default RGA will
                           use the driver that is associated with the primary
                           display adapter.
  --UAVSlot arg            This value should be in the range of [0,63].
                           The driver will use the slot to track which UAV is
                           being used to specify the intrinsic. The UAV slot
                           that is selected cannot be used for any other
                           purposes.
                           This option is only relevant when AMD D3D11 Shader
                           Intrinsics is enabled (specify --intrinsics).

Examples:
  View supported ASICS for DirectX:
    rga.exe -s hlsl -l
  Compile myShader.hlsl for all supported targets and extract the ISA disassembly:
    rga.exe -s hlsl -f VsMain -p vs_5_0 --isa output/myShader_isa.txt src/myShader.hlsl
  Compile myShader.hlsl for Fiji; extract the ISA and perform live register analysis:
    rga.exe -s hlsl -c Fiji -f VsMain -p vs_5_0 --isa output/myShader_isa.txt --livereg output/regs.txt myShader.hlsl
  Compile myShader.hlsl for Radeon R9 390; perform static analysis and save the statistics to myShader.csv:
    rga.exe -s hlsl -c r9-390 -f VsMain -p vs_5_0 -a output/myShader.csv shaders/myShader.hlsl



*/
