use crate::error::{Error, ErrorKind, Result};
use crate::proto::drivers::dxc;
use crate::utilities;

use crate::utilities::{any_as_u8_slice, compute_file_identity, wine_wrap};
use failure::ResultExt;
use filebuffer::FileBuffer;
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::Command;

/*
    Non-determinism notes (issue solved now):

    Contents of the `ILDN` chunk that's changing
    - https://github.com/Microsoft/DirectXShaderCompiler/blob/master/docs/SourceLevelDebuggingHLSL.rst#id8).
    That's the chunk that stores the filename of the symbols file. Looking at the contents of the chunk, it
    looks like the format of the `LLD` symbol filename is generated similarly to how PDB filenames get generated
    (via a linker time date stamp concatenated with the size of the image, or in this case, the size of the
    shader: https://randomascii.wordpress.com/2013/03/09/symbols-the-microsoft-way/).
    Expect that those bytes would change on every build, since the linker time date stamp would get a new build time.

    If you muck with the linker time date stamp or the image size, then you may have trouble finding symbols when you
    go to debug your shaders. If debugging is not your concern, then you could zero that whole string out.

    Alternatively, you could change that string to something more sensible that takes the same number of bytes
    (or less,since it's zero-terminated). It is likely long enough to actually put the name of your shader in there.

    Just make sure that you rename the filename of the `LLD` file to match whatever you change it to! :]

    Using the `/Fd` flag to specify the name of the external debug file.
    https://github.com/Microsoft/DirectXShaderCompiler/blob/master/include/dxc/Support/HLSLOptions.h

    You may need to crawl the `dxc` sourcecode and look for the `DXIL` chunk definition, and then that
    should contain an offset to the start of the IL bytecode, and from there you can walk that to see what
    in the IL is actually generated differently between compiles.
*/

lazy_static! {
    pub static ref DXC_PATH: String = env::var("DXC_PATH")
        .expect("DXC_PATH must be set")
        .to_string();
}

lazy_static! {
    pub static ref DXC_IDENTITY: String =
        { compute_file_identity(Path::new(&*DXC_PATH)).expect("failed to calculate DXC identity") };
}

lazy_static! {
    pub static ref DXC_ENABLED: bool = { env::var("DXC_PATH").is_ok() };
}

#[derive(Default)]
pub struct Compiler {
    options: dxc::CompileOptions,
    include_paths: Vec<String>,
}

pub struct DxcOutput {
    pub code: Vec<u8>,
    pub listing: Vec<u8>,
    pub debug: Vec<u8>,
}

impl Compiler {
    pub fn new(options: &dxc::CompileOptions) -> Self {
        Compiler {
            options: options.to_owned(),
            include_paths: Vec::new(),
        }
    }

    pub fn entry_point(&self) -> &str {
        &self.options.entry_point
    }

    pub fn defines(&self) -> &HashMap<String, String> {
        &self.options.definitions
    }

    pub fn optimization_level(&self) -> dxc::OptimizationLevel {
        dxc::OptimizationLevel::from_i32(self.options.optimization_level).unwrap()
    }

    pub fn warning_level(&self) -> dxc::WarningLevel {
        dxc::WarningLevel::from_i32(self.options.warning_level).unwrap()
    }

    pub fn validation_level(&self) -> dxc::ValidationLevel {
        dxc::ValidationLevel::from_i32(self.options.validation_level).unwrap()
    }

    pub fn code_generation(&self) -> dxc::CodeGeneration {
        dxc::CodeGeneration::from_i32(self.options.code_generation).unwrap()
    }

    pub fn listing_info(&self) -> dxc::ListingInfo {
        dxc::ListingInfo::from_i32(self.options.listing_info).unwrap()
    }

    pub fn debug_info(&self) -> dxc::DebugInfo {
        dxc::DebugInfo::from_i32(self.options.debug_info).unwrap()
    }

    pub fn target_version(&self) -> dxc::TargetVersion {
        dxc::TargetVersion::from_i32(self.options.target_version).unwrap()
    }

    pub fn target_profile(&self) -> dxc::TargetProfile {
        dxc::TargetProfile::from_i32(self.options.target_profile).unwrap()
    }

    pub fn input_format(&self) -> dxc::InputFormat {
        dxc::InputFormat::from_i32(self.options.input_format).unwrap()
    }

    pub fn output_format(&self) -> dxc::OutputFormat {
        dxc::OutputFormat::from_i32(self.options.output_format).unwrap()
    }

    pub fn hlsl_version(&self) -> dxc::HlslVersion {
        dxc::HlslVersion::from_i32(self.options.hlsl_version).unwrap()
    }

    pub fn flow_control(&self) -> dxc::FlowControl {
        dxc::FlowControl::from_i32(self.options.flow_control).unwrap()
    }

    pub fn denorm(&self) -> dxc::DenormLevel {
        dxc::DenormLevel::from_i32(self.options.denorm).unwrap()
    }

    pub fn matrix_packing(&self) -> dxc::MatrixPacking {
        dxc::MatrixPacking::from_i32(self.options.matrix_packing).unwrap()
    }

    pub fn signature_packing(&self) -> dxc::SignaturePacking {
        dxc::SignaturePacking::from_i32(self.options.signature_packing).unwrap()
    }

    pub fn define<'a>(&'_ mut self, name: String, value: String) -> &'_ mut Compiler {
        self.options.definitions.insert(name, value);
        self
    }

    pub fn include_path<'a>(&'a mut self, include_path: &Path) -> &'a mut Compiler {
        let include_path =
            utilities::string_from_path(&include_path).unwrap_or_else(|| "PATH_ERROR".to_string());
        self.include_paths.push(include_path);
        self
    }

    pub fn compile(
        &self,
        working_dir: &Path,
        input_path: &Path,
        output_path: &Path,
        listing_path: &Path,
        debug_path: &Path,
    ) -> Result<(DxcOutput, String)> {
        let (command, mut args) = wine_wrap(DXC_PATH.to_string());

        args.extend(self.cmd_args());

        if self.code_generation() == dxc::CodeGeneration::Enabled {
            args.push("-Fo".to_string());
            args.push(output_path.to_string_lossy().to_string());
        }

        if self.listing_info() == dxc::ListingInfo::Enabled {
            args.push("-Fc".to_string());
            args.push(listing_path.to_string_lossy().to_string());
        }

        self.defines().iter().for_each(|(name, value)| {
            args.push("-D".to_string());
            if value.is_empty() {
                args.push(name.to_owned());
            } else {
                args.push(format!("{}={}", name, value));
            }
        });

        if self.debug_info() == dxc::DebugInfo::Enabled
            && self.output_format() == dxc::OutputFormat::Dxil
        {
            // -Zsb  Build debug name considering only output binary
            // -Zss  Build debug name considering source information
            args.push("-Fd".to_string());
            args.push(debug_path.to_string_lossy().to_string());
        }

        args.push(input_path.to_string_lossy().to_string());

        let mut command_call = Command::new(&command);
        command_call.current_dir(&working_dir);
        for arg in &args {
            command_call.arg(arg);
        }

        let output = command_call.output();
        match output {
            Ok(ref output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if output.status.success() {
                    let mut output_data = DxcOutput {
                        code: Vec::new(),
                        listing: Vec::new(),
                        debug: Vec::new(),
                    };

                    if self.code_generation() == dxc::CodeGeneration::Enabled {
                        let output_buffer = FileBuffer::open(&output_path)
                            .with_context(|_| ErrorKind::path(&output_path))?;
                        output_data.code = output_buffer.to_vec();
                    }

                    if self.listing_info() == dxc::ListingInfo::Enabled {
                        let output_buffer = FileBuffer::open(&listing_path)
                            .with_context(|_| ErrorKind::path(&listing_path))?;
                        output_data.listing = output_buffer.to_vec();
                    }

                    if self.debug_info() == dxc::DebugInfo::Enabled
                        && self.output_format() == dxc::OutputFormat::Dxil
                    {
                        let output_buffer = FileBuffer::open(&debug_path)
                            .with_context(|_| ErrorKind::path(&debug_path))?;
                        output_data.debug = output_buffer.to_vec();
                    }

                    Ok((output_data, stdout.to_string()))
                } else {
                    Err(Error::process(format!(
                        "failed to run command - details: {:?} - {:?} - command was: {}, args: {:?}",
                        stdout.to_string(),
                        stderr.to_string(),
                        command,
                        args,
                    )))
                }
            }
            Err(err) => {
                panic!("Error occurred: {:?}", err);
            }
        }
    }

    #[allow(clippy::cyclomatic_complexity)]
    fn cmd_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        let spirv_path = self.output_format() == dxc::OutputFormat::Spirv
            || self.output_format() == dxc::OutputFormat::Smolv;

        let library_path = match self.target_profile() {
            dxc::TargetProfile::RayGen
            | dxc::TargetProfile::RayIntersection
            | dxc::TargetProfile::RayClosestHit
            | dxc::TargetProfile::RayAnyHit
            | dxc::TargetProfile::RayMiss => true,
            _ => false,
        };

        if !library_path {
            args.push("-E".to_string());
            args.push(self.entry_point().to_owned());
        }

        assert_eq!(self.input_format(), dxc::InputFormat::Hlsl);
        if spirv_path {
            args.push("-spirv".to_string());
        }

        let version_part = match self.target_version() {
            dxc::TargetVersion::V60 => "6_0",
            dxc::TargetVersion::V61 => "6_1",
            dxc::TargetVersion::V62 => "6_2",
            dxc::TargetVersion::V63 => "6_3",
            dxc::TargetVersion::V64 => "6_4",
        };

        let profile_part = match self.target_profile() {
            dxc::TargetProfile::Pixel => "ps",
            dxc::TargetProfile::Vertex => "vs",
            dxc::TargetProfile::Compute => "cs",
            dxc::TargetProfile::Geometry => "gs",
            dxc::TargetProfile::Domain => "ds",
            dxc::TargetProfile::Hull => "hs",
            dxc::TargetProfile::RayGen
            | dxc::TargetProfile::RayIntersection
            | dxc::TargetProfile::RayClosestHit
            | dxc::TargetProfile::RayAnyHit
            | dxc::TargetProfile::RayMiss => "lib",
        };

        args.push("-T".to_string());
        args.push(format!("{}_{}", profile_part, version_part));

        args.push(
            match self.optimization_level() {
                dxc::OptimizationLevel::Off => "-Od",
                dxc::OptimizationLevel::Zero => "-O0",
                dxc::OptimizationLevel::One => "-O1",
                dxc::OptimizationLevel::Two => "-O2",
                dxc::OptimizationLevel::Three => "-O3",
                dxc::OptimizationLevel::Four => "-O4",
            }
            .to_string(),
        );

        args.push("-HV".to_string());
        args.push(
            match self.hlsl_version() {
                dxc::HlslVersion::Edition2016 => "2016",
                dxc::HlslVersion::Edition2017 => "2017",
                dxc::HlslVersion::Edition2018 => "2018",
            }
            .to_string(),
        );

        match self.warning_level() {
            dxc::WarningLevel::Off => {
                args.push("-no-warnings".to_string());
            }
            dxc::WarningLevel::Default => {}
            dxc::WarningLevel::Strict => {
                args.push("-WX".to_string());
            }
        }

        if self.validation_level() == dxc::ValidationLevel::Off {
            args.push("-Vd".to_string());
        }

        if self.debug_info() == dxc::DebugInfo::Enabled {
            args.push("-Zi".to_string());
        }

        match self.flow_control() {
            dxc::FlowControl::Prefer => {
                args.push("-Gfp".to_string());
            }
            dxc::FlowControl::Default => {}
            dxc::FlowControl::Avoid => {
                args.push("-Gfa".to_string());
            }
        }

        if self.target_version() != dxc::TargetVersion::V60
            && self.target_version() != dxc::TargetVersion::V61
        {
            // Only allowed on shader model 6.2+
            args.push("-denorm".to_string());
            match self.denorm() {
                dxc::DenormLevel::Any => {
                    args.push("any".to_string());
                }
                dxc::DenormLevel::Preserve => {
                    args.push("preserve".to_string());
                }
                dxc::DenormLevel::Ftz => {
                    args.push("ftz".to_string());
                }
            }
        }

        match self.matrix_packing() {
            dxc::MatrixPacking::RowMajor => {
                args.push("-Zpr".to_string());
            }
            dxc::MatrixPacking::Default => {}
            dxc::MatrixPacking::ColumnMajor => {
                args.push("-Zpc".to_string());
            }
        }

        match self.signature_packing() {
            dxc::SignaturePacking::PrefixStable => {
                args.push("-pack_prefix_stable".to_string());
            }
            dxc::SignaturePacking::Optimized => {
                args.push("-pack_optimized".to_string());
            }
        }

        if self.options.all_resources_bound {
            args.push("-all_resources_bound".to_string());
        }

        if self.options.enable_16bit_types {
            args.push("-enable-16bit-types".to_string());
        }

        if self.options.legacy_macro_expansion {
            args.push("-flegacy-macro-expansion".to_string());
        }

        if self.options.color_coded_listing {
            args.push("-Cc".to_string());
        }

        if self.options.strict_mode {
            args.push("-Ges".to_string());
        }

        if self.options.force_ieee {
            args.push("-Gis".to_string());
        }

        if self.options.output_include_depth {
            args.push("-H".to_string());
        }

        if self.options.output_include_details {
            args.push("-Vi".to_string());
        }

        if self.options.output_hex_literals {
            args.push("-Lx".to_string());
        }

        if self.options.output_instruction_numbers {
            args.push("-Ni".to_string());
        }

        if self.options.output_instruction_offsets {
            args.push("-No".to_string());
        }

        if self.options.output_optimizer_commands {
            args.push("-Odump".to_string());
        }

        if self.options.ignore_line_directives {
            args.push("-ignore-line-directives".to_string());
        }

        if self.options.deny_legacy_cbuffer_load {
            args.push("-not_use_legacy_cbuf_load".to_string());
        }

        if let Some(ref spirv) = self.options.spirv {
            // Only include SPIR-V options if that is the output format
            if self.output_format() == dxc::OutputFormat::Spirv
                || self.output_format() == dxc::OutputFormat::Smolv
            {
                let version = dxc::VulkanVersion::from_i32(spirv.version).unwrap();
                match version {
                    dxc::VulkanVersion::Vulkan10 => {
                        args.push("-fspv-target-env=vulkan1.0".to_string())
                    }
                    dxc::VulkanVersion::Vulkan11 => {
                        args.push("-fspv-target-env=vulkan1.1".to_string())
                    }
                }

                let resource_layout =
                    dxc::VulkanResourceLayout::from_i32(spirv.resource_layout).unwrap();
                match resource_layout {
                    dxc::VulkanResourceLayout::Dx => args.push("-fvk-use-dx-layout".to_string()),
                    dxc::VulkanResourceLayout::Gl => args.push("-fvk-use-gl-layout".to_string()),
                }

                if spirv.emit_reflection {
                    args.push("-fspv-reflect".to_string());
                }

                if spirv.dx_position_w {
                    args.push("-fvk-use-dx-position-w".to_string());
                }

                if spirv.invert_y {
                    args.push("-fvk-invert-y".to_string());
                }

                for binding_shift in &spirv.binding_shifts {
                    let binding_type =
                        dxc::VulkanBindingType::from_i32(binding_shift.binding_type).unwrap();
                    match binding_type {
                        dxc::VulkanBindingType::B => args.push("-fvk-b-shift".to_string()),
                        dxc::VulkanBindingType::S => args.push("-fvk-s-shift".to_string()),
                        dxc::VulkanBindingType::T => args.push("-fvk-t-shift".to_string()),
                        dxc::VulkanBindingType::U => args.push("-fvk-u-shift".to_string()),
                    }
                    args.push(format!("{}", binding_shift.shift));
                    args.push(format!("{}", binding_shift.space));
                }

                for binding_register in &spirv.binding_registers {
                    args.push("-fvk-bind-register".to_string());
                    args.push(format!("{}", binding_register.type_number));
                    args.push(format!("{}", binding_register.space));
                    args.push(format!("{}", binding_register.binding));
                    args.push(format!("{}", binding_register.set));
                }

                for info in &spirv.debug_info {
                    args.push(format!("-fspv-debug={}", info));
                }

                for extension in &spirv.extensions {
                    args.push(format!("-fspv-extension={}", extension));
                }

                let mut opt_config = String::new();
                for config in &spirv.opt_config {
                    if opt_config.is_empty() {
                        opt_config += &config.to_string();
                    } else {
                        opt_config += &format!(",{}", config);
                    }
                }

                if !opt_config.is_empty() {
                    args.push(format!("-Oconfig={}", opt_config));
                }
            }
        }

        for include_path in &self.include_paths {
            // Add directory to include search path
            args.push("-I".to_string());
            args.push(include_path.to_owned());
        }

        args
    }
}

pub fn identity_from_request(source_identity: &str, options: &dxc::CompileOptions) -> String {
    use base58::ToBase58;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::default();
    hasher.input(&*DXC_IDENTITY.as_bytes());
    hasher.input(&source_identity.as_bytes());
    hasher.input(&options.entry_point.as_bytes());
    options.definitions.iter().for_each(|(name, value)| {
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
    }
    hasher.result().to_vec().to_base58()
}

/*

USAGE: dxc.exe [options] <inputs>

Common Options:
  -help              Display available options
  -nologo            Suppress copyright message
  -Qunused-arguments Don't emit warning for unused driver arguments

Compilation Options:
  -all_resources_bound    Enables agressive flattening
  -Cc                     Output color coded assembly listings
  -denorm <value>         select denormal value options (any, preserve, ftz). any is the default.
  -D <value>              Define macro
  -enable-16bit-types     Enable 16bit types and disable min precision types. Available in HLSL 2018 and shader model 6.2
  -E <value>              Entry point name
  -Fc <file>              Output assembly code listing file
  -Fd <file>              Write debug information to the given file or directory; trail \ to auto-generate and imply Qstrip_priv
  -Fe <file>              Output warnings and errors to the given file
  -Fh <file>              Output header file containing object code
  -flegacy-macro-expansion
                          Expand the operands before performing token-pasting operation (fxc behavior)
  -force_rootsig_ver <profile>
                          force root signature version (rootsig_1_1 if omitted)
  -Fo <file>              Output object file
  -Ges                    Enable strict mode
  -Gfa                    Avoid flow control constructs
  -Gfp                    Prefer flow control constructs
  -Gis                    Force IEEE strictness
  -HV <value>             HLSL version (2016, 2017, 2018). Default is 2018
  -H                      Show header includes and nesting depth
  -ignore-line-directives Ignore line directives
  -I <value>              Add directory to include search path
  -Lx                     Output hexadecimal literals
  -Ni                     Output instruction numbers in assembly listings
  -no-warnings            Suppress warnings
  -not_use_legacy_cbuf_load
                          Do not use legacy cbuffer load
  -No                     Output instruction byte offsets in assembly listings
  -Odump                  Print the optimizer commands.
  -Od                     Disable optimizations
  -pack_optimized         Optimize signature packing assuming identical signature provided for each connecting stage
  -pack_prefix_stable     (default) Pack signatures preserving prefix-stable property - appended elements will not disturb placement of prior elements
  -recompile              recompile from DXIL container with Debug Info or Debug Info bitcode file
  -rootsig-define <value> Read root signature from a #define
  -T <profile>            Set target profile.
        <profile>: ps_6_0, ps_6_1, ps_6_2, vs_6_0, vs_6_1, vs_6_2,
                 cs_6_0, cs_6_1, cs_6_2, gs_6_0, gs_6_1, gs_6_2,
                 ds_6_0, ds_6_1, ds_6_2, hs_6_0, hs_6_1, hs_6_2,
                 lib_6_0, lib_6_1, lib_6_2
  -Vd                     Disable validation
  -Vi                     Display details about the include process.
  -Vn <name>              Use <name> as variable name in header file
  -WX                     Treat warnings as errors
  -Zi                     Enable debug information
  -Zpc                    Pack matrices in column-major order
  -Zpr                    Pack matrices in row-major order
  -Zsb                    Build debug name considering only output binary
  -Zss                    Build debug name considering source information

Optimization Options:
  -O0 Optimization Level 0
  -O1 Optimization Level 1
  -O2 Optimization Level 2
  -O3 Optimization Level 3 (Default)
  -O4 Optimization Level 4

SPIR-V CodeGen Options:
  -fspv-debug=<value>     Specify whitelist of debug info category (file -> source -> line, tool)
  -fspv-extension=<value> Specify SPIR-V extension permitted to use
  -fspv-reflect           Emit additional SPIR-V instructions to aid reflection
  -fspv-target-env=<value>
                          Specify the target environment: vulkan1.0 (default) or vulkan1.1
  -fvk-b-shift <shift> <space>
                          Specify Vulkan binding number shift for b-type register
  -fvk-bind-register <type-number> <space> <binding> <set>
                          Specify Vulkan descriptor set and binding for a specific register
  -fvk-invert-y           Negate SV_Position.y before writing to stage output in VS/DS/GS to accommodate Vulkan's coordinate system
  -fvk-s-shift <shift> <space>
                          Specify Vulkan binding number shift for s-type register
  -fvk-t-shift <shift> <space>
                          Specify Vulkan binding number shift for t-type register
  -fvk-u-shift <shift> <space>
                          Specify Vulkan binding number shift for u-type register
  -fvk-use-dx-layout      Use DirectX memory layout for Vulkan resources
  -fvk-use-dx-position-w  Reciprocate SV_Position.w after reading from stage input in PS to accommodate the difference between Vulkan and DirectX
  -fvk-use-gl-layout      Use strict OpenGL std140/std430 memory layout for Vulkan resources
  -Oconfig=<value>        Specify a comma-separated list of SPIRV-Tools passes to customize optimization configuration (see http://khr.io/hlsl2spirv#optimization)
  -spirv                  Generate SPIR-V code

Utility Options:
  -dumpbin              Load a binary file rather than compiling
  -extractrootsignature Extract root signature from shader bytecode (must be used with /Fo <file>)
  -getprivate <file>    Save private data from shader blob
  -P <value>            Preprocess to file (must be used alone)
  -Qstrip_debug         Strip debug information from 4_0+ shader bytecode  (must be used with /Fo<file>)
  -Qstrip_priv          Strip private data from shader bytecode  (must be used with /Fo <file>)
  -Qstrip_reflect       Strip reflection data from shader bytecode  (must be used with /Fo <file>)
  -Qstrip_rootsignature Strip root signature data from shader bytecode  (must be used with /Fo <file>)
  -setprivate <file>    Private data to add to compiled shader blob
  -setrootsignature <file>
                        Attach root signature to shader bytecode
  -verifyrootsignature <file>
                        Verify shader bytecode with root signature

*/
