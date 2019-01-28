use crate::error::{ErrorKind, Result};
use crate::identity::{compute_data_identity, Identity};
use crate::utilities::read_file;
use failure::ResultExt;
use std::path::{Path, PathBuf};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ShaderContent {
    pub data: Option<Vec<u8>>,
    pub name: Option<String>,
    pub path: Option<(PathBuf, PathBuf)>,
    pub ident: Option<Identity>,
    pub references: Vec<ShaderReference>,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ShaderReference {
    pub path: PathBuf,
    pub range_start: usize,
    pub range_end: usize,
}

impl ShaderContent {
    pub fn new_with_data(
        name: &str,
        data: &[u8],
        ident: Option<Identity>,
    ) -> Result<ShaderContent> {
        Ok(ShaderContent {
            data: Some(data.to_vec()),
            name: Some(name.to_string()),
            path: None,
            ident,
            references: Vec::new(),
        })
    }

    pub fn new_with_file(parent: &Path, path: &Path) -> Result<ShaderContent> {
        let full_path = parent.join(&path);
        let canonical_path = full_path
            .canonicalize()
            .with_context(|_| ErrorKind::path(&full_path))?;
        Ok(ShaderContent {
            data: None,
            name: None,
            path: Some((path.to_path_buf(), canonical_path)),
            ident: None,
            references: Vec::new(),
        })
    }

    pub fn compute_identity(&mut self) -> Result<()> {
        if self.ident.is_none() {
            if let Some(ref data) = self.data {
                self.ident = Some(compute_data_identity(data));
            }
        }
        Ok(())
    }

    pub fn reload_data(&mut self) -> Result<()> {
        if let Some((ref _path, ref canonical)) = self.path {
            self.data = Some(read_file(canonical).unwrap());
            self.ident = None;
        }
        Ok(())
    }

    pub fn data_as_string(&self) -> String {
        if let Some(ref data) = self.data {
            String::from_utf8_lossy(data).to_string()
        } else {
            String::new()
        }
    }

    pub fn data_from_string(&mut self, content: &str) -> Result<()> {
        self.data = Some(content.as_bytes().to_vec());
        self.ident = None;
        self.compute_identity()?;
        Ok(())
    }

    pub fn identity_as_string(&self) -> String {
        if let Some(ref identity) = self.ident {
            identity.txt.to_owned()
        } else {
            String::from("NO_IDENTITY")
        }
    }

    pub fn patch_references(
        &self,
        patches: &[(&ShaderReference, String)],
    ) -> Result<ShaderContent> {
        let mut shader_text = self.data_as_string();
        for patch in patches {
            shader_text.replace_range(patch.0.range_start..patch.0.range_end, &patch.1);
        }

        let data = shader_text.as_bytes();
        let ident = compute_data_identity(data);
        let name = ident.txt.to_owned();

        Ok(ShaderContent::new_with_data(&name, &data, Some(ident))?)
    }
}
