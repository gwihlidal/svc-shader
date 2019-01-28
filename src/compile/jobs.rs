//use crate::compile_entry;
use crate::compile::ShaderEntry;
use scoped_threadpool::Pool;
use std::path::Path;

#[derive(Default, Debug, Clone)]
pub struct ShaderCompileOutput {
    pub name: String,
    pub hash: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Default, Debug, Clone)]
pub struct ShaderCompileWork {
    pub entry: ShaderEntry,
    pub input: Vec<u8>,
    pub output: Vec<ShaderCompileOutput>,
}

pub fn enqueue_shader_work(
    _base_dir: &Path,
    entries: &[ShaderEntry],
    thread_count: u32,
) -> Vec<ShaderCompileWork> {
    let mut work_items: Vec<ShaderCompileWork> = entries
        .iter()
        .map(|entry| ShaderCompileWork {
            entry: entry.clone(),
            input: Vec::new(),
            output: Vec::new(),
        })
        .collect();

    let mut pool = Pool::new(thread_count);
    pool.scoped(|scoped| {
        for _work_item in &mut work_items {
            scoped.execute(move || {
                /*compile_entry(base_dir, &work_item.entry);
                work_item.output.push(ShaderCompileOutput {
                    name: "DXIL".to_string(),
                    hash: vec![0, 1, 2, 3],
                    data: vec![4, 5, 6, 7],
                });*/
            });
        }
    });

    work_items
}
