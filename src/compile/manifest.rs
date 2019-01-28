use crate::error::{Error, ErrorKind, Result};
use crate::utilities::{path_exists, read_file_string};
use failure::ResultExt;
use std::path::Path;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ShaderEntry {
    pub name: String,
    pub profile: String,
    pub entry_point: String,
    pub entry_file: String,
    pub output: Vec<String>,
    pub defines: Option<Vec<String>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ParsedShaderEntry {
    pub name: String,
    pub profile: String,
    pub entry_point: String,
    pub identity: String,
    pub language: String,
    pub output: Vec<String>,
    pub defines: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShaderManifest {
    pub entries: Vec<ShaderEntry>,
}

impl ShaderManifest {
    pub fn validate(&self, base_dir: &Path) -> Result<()> {
        // TODO: Improve this a lot
        //   - Valid profile? cs, vs, ps, lb, ms, ts, etc..
        //   - Valid output? dxil, spirv, etc..
        //   - Entry point?
        //   - Names are unique
        //   - Settings
        for entry in &self.entries {
            let shader_file = base_dir.join(&entry.entry_file);
            if !path_exists(&shader_file) {
                return Err(Error::config(format!(
                    "file {:?} does not exist",
                    shader_file
                )));
            }
        }
        Ok(())
    }
}

pub fn load_manifest(base_dir: &Path, path: &Path) -> Result<ShaderManifest> {
    let manifest_toml = read_file_string(&path).with_context(|_| ErrorKind::path(path))?;
    parse_manifest(base_dir, &manifest_toml)
}

pub fn parse_manifest(base_dir: &Path, manifest_toml: &str) -> Result<ShaderManifest> {
    let manifest: ShaderManifest = toml::from_str(&manifest_toml)?;
    manifest.validate(&base_dir)?;
    Ok(manifest)
}
