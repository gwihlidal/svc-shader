use crate::utilities;
use regex::Regex;
use std::path::Path;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct IncludeReference {
    pub include_path: String,
    pub range_start: usize,
    pub range_end: usize,
    pub relative_path: bool,
}

pub fn parse_includes(input: &str) -> Vec<IncludeReference> {
    //r#"(?m)^*\#include\s+["<]([^">]+)*[">]"#
    //r#"(?m)(^*\#\s*include\s*<([^<>]+)>)|(^\s*\#\s*include\s*"([^"]+)")"#

    lazy_static! {
        static ref ABSOLUTE_PATH_REGEX: Regex = Regex::new(r#"(?m)^*\#\s*include\s*<([^<>]+)>"#)
            .expect("failed to compile absolute include path regex");
    }

    lazy_static! {
        static ref RELATIVE_PATH_REGEX: Regex = Regex::new(r#"(?m)^*\#\s*include\s*"([^"]+)""#)
            .expect("failed to compile relative include path regex");
    }

    let mut references: Vec<IncludeReference> = Vec::with_capacity(8);

    // Result will be an iterator over tuples containing the start and end indices for each match in the string
    let absolute_results = ABSOLUTE_PATH_REGEX.find_iter(input);
    for absolute_result in absolute_results {
        let range_start = absolute_result.start();
        let range_end = absolute_result.end();
        let range_text = &input[range_start..range_end];
        let range_caps = ABSOLUTE_PATH_REGEX.captures(range_text).unwrap();
        let include_path = range_caps.get(1).map_or("", |m| m.as_str());
        if !include_path.is_empty() {
            references.push(IncludeReference {
                include_path: include_path.to_owned(),
                range_start,
                range_end,
                relative_path: false,
            });
        }
    }

    let relative_results = RELATIVE_PATH_REGEX.find_iter(input);
    for relative_result in relative_results {
        let range_start = relative_result.start();
        let range_end = relative_result.end();
        let range_text = &input[range_start..range_end];
        let range_text = range_text.trim().trim_matches('\n');
        let range_caps = RELATIVE_PATH_REGEX.captures(range_text).unwrap();
        let include_path = range_caps.get(1).map_or("", |m| m.as_str());
        if !include_path.is_empty() {
            references.push(IncludeReference {
                include_path: include_path.to_owned(),
                range_start,
                range_end,
                relative_path: true,
            });
        }
    }

    references
}

pub fn parse_includes_recursive(
    input: &str,
    root_dir: &Path,
    file_dir: &Path,
    result: &mut Vec<IncludeReference>,
) {
    let mut includes = get_references(&input, root_dir, file_dir);

    for include in &includes {
        let input = utilities::read_file_string(&include.include_path);
        match input {
            Ok(input) => {
                let mut inner_result = Vec::new();
                let file_dir = Path::new(&include.include_path).parent().unwrap();
                parse_includes_recursive(&input, root_dir, file_dir, &mut inner_result);
                result.append(&mut inner_result);
            }
            Err(_) => {
                println!(
                    "Failed to open include (does not exist): {:?}",
                    include.include_path
                );
            }
        }
    }

    result.append(&mut includes);
}

pub fn path_resolve(
    references: &[IncludeReference],
    root_dir: &Path,
    file_dir: &Path,
) -> Vec<IncludeReference> {
    let mut result = references.to_owned();
    for reference in &mut result {
        let parent_path = if reference.relative_path {
            file_dir
        } else {
            root_dir
        };

        let full_path = parent_path.join(&reference.include_path);
        match full_path.canonicalize() {
            Ok(resolved) => {
                reference.include_path = utilities::string_from_path(&resolved).unwrap();
            }
            Err(err) => {
                trace!("Error resolving path! {:?} - {:?}", full_path, err);
            }
        }
    }

    result.retain(|reference| {
        let include_path = Path::new(&reference.include_path);
        let exists = utilities::path_exists(&include_path);
        if !exists {
            warn!("Include path is invalid: {:?}", include_path);
        }
        exists
    });

    result
}

pub fn path_dedup(references: &[IncludeReference]) -> Vec<IncludeReference> {
    // Assume all paths have been expanded to their absolute form
    let mut result = references.to_owned();
    result.sort_by(|a, b| a.include_path.cmp(&b.include_path));
    result.dedup_by(|a, b| a.include_path.eq(&b.include_path));
    result
}

pub fn range_sort(references: &[IncludeReference]) -> Vec<IncludeReference> {
    let mut result = references.to_owned();
    result.sort_by(|a, b| a.range_start.cmp(&b.range_start));
    result
}

pub fn range_sort_rev(references: &[IncludeReference]) -> Vec<IncludeReference> {
    let mut result = references.to_owned();
    result.sort_by(|a, b| b.range_start.cmp(&a.range_start));
    result
}

pub fn get_references(text: &str, root_dir: &Path, file_dir: &Path) -> Vec<IncludeReference> {
    let raw_references = parse_includes(&text);
    let resolved_references = path_resolve(&raw_references, &root_dir, &file_dir);
    range_sort(&path_dedup(&resolved_references))
}

pub fn strip_base(root_dir: &Path, references: &[IncludeReference]) -> Vec<IncludeReference> {
    let prefix = root_dir.canonicalize().unwrap();
    let mut result = references.to_owned();
    for reference in &mut result {
        let include_path = Path::new(&reference.include_path);
        let include_path = include_path.strip_prefix(&prefix).unwrap();
        reference.include_path = utilities::string_from_path(&include_path).unwrap();
    }
    result
}
