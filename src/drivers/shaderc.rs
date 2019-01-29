use crate::error::{Error, ErrorKind, Result};
use crate::proto::drivers::shaderc;
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
    Glsl,
}

pub enum OutputFormat {
    Spirv,
}

lazy_static! {
    pub static ref GLSLC_PATH: String = env::var("GLSLC_PATH")
        .expect("GLSLC_PATH must be set")
        .to_string();
}

lazy_static! {
    pub static ref GLSLC_IDENTITY: String = {
        compute_file_identity(Path::new(&*GLSLC_PATH)).expect("failed to calculate GLSLC identity")
    };
}

lazy_static! {
    pub static ref GLSLC_ENABLED: bool = { env::var("GLSLC_PATH").is_ok() };
}

pub struct GlslcOutput {
    pub code: Vec<u8>,
}

#[derive(Default)]
pub struct Compiler {
    options: shaderc::CompileOptions,
    include_paths: Vec<String>,
}

impl Compiler {
    pub fn new(options: &shaderc::CompileOptions) -> Self {
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

    pub fn optimization_level(&self) -> shaderc::OptimizationLevel {
        shaderc::OptimizationLevel::from_i32(self.options.optimization_level).unwrap()
    }

    pub fn warning_level(&self) -> shaderc::WarningLevel {
        shaderc::WarningLevel::from_i32(self.options.warning_level).unwrap()
    }

    pub fn debug_info(&self) -> shaderc::DebugInfo {
        shaderc::DebugInfo::from_i32(self.options.debug_info).unwrap()
    }

    pub fn target_profile(&self) -> shaderc::TargetProfile {
        shaderc::TargetProfile::from_i32(self.options.target_profile).unwrap()
    }

    pub fn input_format(&self) -> shaderc::InputFormat {
        shaderc::InputFormat::from_i32(self.options.input_format).unwrap()
    }

    pub fn output_format(&self) -> shaderc::OutputFormat {
        shaderc::OutputFormat::from_i32(self.options.output_format).unwrap()
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

    fn cmd_args(&self) -> Vec<String> {
        assert!(
            self.output_format() == shaderc::OutputFormat::Spirv
                || self.output_format() == shaderc::OutputFormat::Smolv
        );

        let mut args = Vec::new();

        args.push(format!("-fentry-point={}", self.entry_point()));

        if self.input_format() == shaderc::InputFormat::Hlsl {
            args.push("-x".to_string());
            args.push("hlsl".to_string());
        } else if self.input_format() == shaderc::InputFormat::Glsl {
            args.push("-x".to_string());
            args.push("glsl".to_string());
        }

        let version = shaderc::VulkanVersion::from_i32(self.options.version).unwrap();
        match version {
            shaderc::VulkanVersion::Vulkan10 => args.push("--target-env=vulkan1.0".to_string()),
            shaderc::VulkanVersion::Vulkan11 => args.push("--target-env=vulkan1.1".to_string()),
        }

        args.push(format!(
            "-fshader-stage={}",
            profile_to_string(self.target_profile())
        ));

        args.push(
            match self.optimization_level() {
                shaderc::OptimizationLevel::Off => "-O0",
                shaderc::OptimizationLevel::Size => "-Os",
                shaderc::OptimizationLevel::Perf => "-O",
            }
            .to_string(),
        );

        match self.warning_level() {
            shaderc::WarningLevel::Off => {
                args.push("-w".to_string());
            }
            shaderc::WarningLevel::Default => {}
            shaderc::WarningLevel::Strict => {
                args.push("-Werror".to_string());
            }
        }

        if self.debug_info() == shaderc::DebugInfo::Enabled {
            args.push("-g".to_string());
        }

        if self.options.auto_bind_uniforms {
            args.push("-fauto-bind-uniforms".to_string());
        }

        if self.options.auto_map_locations {
            args.push("-fauto-map-locations".to_string());
        }

        if self.options.hlsl_functionality1 {
            args.push("-fhlsl_functionality1".to_string());
        }

        if self.options.hlsl_iomap {
            args.push("-fhlsl-iomap".to_string());
        }

        if self.options.hlsl_offsets {
            args.push("-fhlsl-offsets".to_string());
        }

        if !self.options.std.is_empty() {
            args.push(format!("-std={}", self.options.std));
        }

        for binding_base in &self.options.binding_bases {
            let binding_type =
                shaderc::VulkanBindingType::from_i32(binding_base.binding_type).unwrap();
            match binding_type {
                shaderc::VulkanBindingType::CBuffer => {
                    args.push("-fcbuffer-binding-base".to_string())
                }
                shaderc::VulkanBindingType::Image => args.push("-fimage-binding-base".to_string()),
                shaderc::VulkanBindingType::Sampler => {
                    args.push("-fsampler-binding-base".to_string())
                }
                shaderc::VulkanBindingType::Ssbo => args.push("-fssbo-binding-base".to_string()),
                shaderc::VulkanBindingType::Texture => {
                    args.push("-ftexture-binding-base".to_string())
                }
                shaderc::VulkanBindingType::Uav => args.push("-fuav-binding-base".to_string()),
                shaderc::VulkanBindingType::Ubo => args.push("-fubo-binding-base".to_string()),
            }
            args.push(format!("{}", binding_base.value));
        }

        for binding_stage_base in &self.options.binding_stage_bases {
            let stage = shaderc::TargetProfile::from_i32(binding_stage_base.stage).unwrap();
            let binding_type =
                shaderc::VulkanBindingType::from_i32(binding_stage_base.binding_type).unwrap();
            match binding_type {
                shaderc::VulkanBindingType::CBuffer => {
                    args.push("-fcbuffer-binding-base".to_string())
                }
                shaderc::VulkanBindingType::Image => args.push("-fimage-binding-base".to_string()),
                shaderc::VulkanBindingType::Sampler => {
                    args.push("-fsampler-binding-base".to_string())
                }
                shaderc::VulkanBindingType::Ssbo => args.push("-fssbo-binding-base".to_string()),
                shaderc::VulkanBindingType::Texture => {
                    args.push("-ftexture-binding-base".to_string())
                }
                shaderc::VulkanBindingType::Uav => args.push("-fuav-binding-base".to_string()),
                shaderc::VulkanBindingType::Ubo => args.push("-fubo-binding-base".to_string()),
            }
            args.push(profile_to_string(stage).to_string());
            args.push(format!("{}", binding_stage_base.value));
        }

        for register_base in &self.options.register_bases {
            args.push("-fresource-set-binding".to_string());
            args.push(format!("{}", register_base.reg0));
            args.push(format!("{}", register_base.set0));
            args.push(format!("{}", register_base.binding0));
        }

        for register_stage_base in &self.options.register_stage_bases {
            let stage = shaderc::TargetProfile::from_i32(register_stage_base.stage).unwrap();
            args.push("-fresource-set-binding".to_string());
            args.push(profile_to_string(stage).to_string());
            args.push(format!("{}", register_stage_base.reg0));
            args.push(format!("{}", register_stage_base.set0));
            args.push(format!("{}", register_stage_base.binding0));
        }

        for include_path in &self.include_paths {
            // Add directory to include search path
            args.push("-I".to_string());
            args.push(include_path.to_owned());
        }

        args
    }

    pub fn compile(
        &self,
        working_dir: &Path,
        input_path: &Path,
        output_path: &Path,
    ) -> Result<(GlslcOutput, String)> {
        let input_file = input_path.file_name().unwrap();
        let output_file = output_path.file_name().unwrap();

        let input_file = input_file.to_string_lossy();
        let output_file = output_file.to_string_lossy();

        let (command, mut args) = wine_wrap(GLSLC_PATH.to_string());

        args.extend(self.cmd_args());

        args.push("-o".to_string());
        args.push(output_file.to_string());

        self.defines().iter().for_each(|(name, value)| {
            let define = if value.is_empty() {
                format!("-D{}", name)
            } else {
                format!("-D{}={}", name, value)
            };
            args.push(define);
        });

        args.push(input_file.to_string());

        let mut output = Command::new(command);
        output.current_dir(&working_dir);
        for arg in &args {
            output.arg(arg);
        }

        let output = output.output();
        match output {
            Ok(ref output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if output.status.success() {
                    let mut output_data = GlslcOutput { code: Vec::new() };

                    let output_buffer = FileBuffer::open(&output_path)
                        .with_context(|_| ErrorKind::path(&output_path))?;
                    output_data.code = output_buffer.to_vec();

                    Ok((output_data, stdout.to_string()))
                } else {
                    Err(Error::process(format!(
                        "failed to run command - details: {:?} - {:?}",
                        stdout.to_string(),
                        stderr.to_string()
                    )))
                }
            }
            Err(err) => {
                panic!("Error occurred: {:?}", err);
            }
        }
    }
}

pub fn profile_to_string(profile: shaderc::TargetProfile) -> &'static str {
    match profile {
        shaderc::TargetProfile::Pixel => "frag",
        shaderc::TargetProfile::Vertex => "vert",
        shaderc::TargetProfile::Compute => "comp",
        shaderc::TargetProfile::Geometry => "geom",
        shaderc::TargetProfile::Domain => "tesseval",
        shaderc::TargetProfile::Hull => "tessc",
        shaderc::TargetProfile::Task => "task",
        shaderc::TargetProfile::Mesh => "mesh",
        shaderc::TargetProfile::RayGen => "rgen",
        shaderc::TargetProfile::RayIntersection => "rint",
        shaderc::TargetProfile::RayClosestHit => "rchit",
        shaderc::TargetProfile::RayAnyHit => "rahit",
        shaderc::TargetProfile::RayMiss => "rmiss",
    }
}

pub fn identity_from_request(source_identity: &str, options: &shaderc::CompileOptions) -> String {
    use base58::ToBase58;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::default();
    hasher.input(&*GLSLC_IDENTITY.as_bytes());
    hasher.input(&source_identity.as_bytes());
    hasher.input(&options.entry_point.as_bytes());
    options.definitions.iter().for_each(|(name, value)| {
        hasher.input(&name.as_bytes());
        hasher.input(&value.as_bytes());
    });
    hasher.input(&unsafe { any_as_u8_slice(&options.input_format) });
    hasher.input(&unsafe { any_as_u8_slice(&options.output_format) });
    hasher.input(&unsafe { any_as_u8_slice(&options.target_profile) });
    hasher.input(&unsafe { any_as_u8_slice(&options.version) });
    hasher.input(&unsafe { any_as_u8_slice(&options.optimization_level) });
    hasher.input(&unsafe { any_as_u8_slice(&options.warning_level) });
    hasher.input(&unsafe { any_as_u8_slice(&options.debug_info) });
    hasher.input(&unsafe { any_as_u8_slice(&options.auto_bind_uniforms) });
    hasher.input(&unsafe { any_as_u8_slice(&options.auto_map_locations) });
    hasher.input(&unsafe { any_as_u8_slice(&options.hlsl_functionality1) });
    hasher.input(&unsafe { any_as_u8_slice(&options.hlsl_iomap) });
    hasher.input(&unsafe { any_as_u8_slice(&options.hlsl_offsets) });
    hasher.input(&options.std.as_bytes());
    options.binding_bases.iter().for_each(|binding| {
        hasher.input(&unsafe { any_as_u8_slice(&binding.binding_type) });
        hasher.input(&unsafe { any_as_u8_slice(&binding.value) });
    });
    options.binding_stage_bases.iter().for_each(|binding| {
        hasher.input(&unsafe { any_as_u8_slice(&binding.binding_type) });
        hasher.input(&unsafe { any_as_u8_slice(&binding.stage) });
        hasher.input(&unsafe { any_as_u8_slice(&binding.value) });
    });
    options.register_bases.iter().for_each(|binding| {
        hasher.input(&unsafe { any_as_u8_slice(&binding.reg0) });
        hasher.input(&unsafe { any_as_u8_slice(&binding.set0) });
        hasher.input(&unsafe { any_as_u8_slice(&binding.binding0) });
    });
    options.register_stage_bases.iter().for_each(|binding| {
        hasher.input(&unsafe { any_as_u8_slice(&binding.stage) });
        hasher.input(&unsafe { any_as_u8_slice(&binding.reg0) });
        hasher.input(&unsafe { any_as_u8_slice(&binding.set0) });
        hasher.input(&unsafe { any_as_u8_slice(&binding.binding0) });
    });
    hasher.result().to_vec().to_base58()
}
