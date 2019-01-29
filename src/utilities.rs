use filebuffer::FileBuffer;
use normalize_line_endings::normalized;
use std::env;
use std::fs::File;
use std::io::Read;
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::{hash::Hasher, io};
use uuid::Uuid;

#[inline(always)]
pub unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
}

pub fn compute_identity(data: &[u8]) -> String {
    use base58::ToBase58;
    use sha2::{Digest, Sha256};

    // create a Sha256 object
    let mut hasher = Sha256::default();

    // write input data
    hasher.input(data);

    // read hash digest and consume hasher
    hasher.result().to_vec().to_base58()
}

struct HashWriter<T: Hasher>(T);
impl<T: Hasher> io::Write for HashWriter<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf);
        Ok(buf.len())
    }
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write(buf).map(|_| ())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// This looks first for linker-inserted build ID / binary UUIDs (i.e.
/// `.note.gnu.build-id` on Linux; `LC_UUID` in Mach-O; etc), falling back to
/// hashing the whole binary.
lazy_static! {
    pub static ref BUILD_ID: String = {
        let mut hasher = twox_hash::XxHash::with_seed(0);

        // let a = |x:()|x;
        // let b = |x:u8|x;
        // hasher.write_u64(type_id(&a));
        // hasher.write_u64(type_id(&b));

        // LC_UUID https://opensource.apple.com/source/libsecurity_codesigning/libsecurity_codesigning-55037.6/lib/machorep.cpp https://stackoverflow.com/questions/10119700/how-to-get-mach-o-uuid-of-a-running-process
        // .note.gnu.build-id https://github.com/golang/go/issues/21564 https://github.com/golang/go/blob/178307c3a72a9da3d731fecf354630761d6b246c/src/cmd/go/internal/buildid/buildid.go
        let file = exe().unwrap();
        let _ = io::copy(&mut &file, &mut HashWriter(&mut hasher)).unwrap();

        let mut bytes = [0; 16];
        <byteorder::NativeEndian as byteorder::ByteOrder>::write_u64(&mut bytes, hasher.finish());
        compute_identity(&bytes)
        //Uuid::from_random_bytes(bytes)
    };
}

pub fn compute_file_identity<P: AsRef<Path>>(path: P) -> io::Result<String> {
    use base58::ToBase58;
    use sha2::{Digest, Sha256};

    let fbuffer = FileBuffer::open(&path)?;

    // create a Sha256 object
    let mut hasher = Sha256::default();

    // write input data
    hasher.input(&fbuffer);

    // read hash digest and consume hasher
    Ok(hasher.result().to_vec().to_base58())
}

lazy_static! {
    pub static ref WINE_PATH: String = env::var("WINE_PATH").unwrap().to_string();
}

cfg_if! {
    if #[cfg(windows)] {
        pub fn wine_wrap(cmd: String) -> (String, Vec<String>) { (cmd, Vec::new()) }
    } else {
        pub fn wine_wrap(cmd: String) -> (String, Vec<String>) {
            if cmd.ends_with(".exe") {
                (WINE_PATH.to_string(), vec![cmd])
            } else {
                (cmd, Vec::new())
            }
        }
    }
}

pub fn path_exists<P: AsRef<Path>>(path: P) -> bool {
    std::fs::metadata(path.as_ref()).is_ok()
}

pub fn read_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    let size = meta.len() as usize;
    let mut data = vec![0; size];
    file.read_exact(&mut data)?;
    Ok(data)
}

pub fn read_file_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(path.as_ref())?;
    let mut text = String::new();
    if let Ok(meta) = file.metadata() {
        text.reserve(meta.len() as usize); // Safe to truncate, since it's only a suggestion
    }
    file.read_to_string(&mut text)?;
    let text = String::from_iter(normalized(text.chars()));
    Ok(text)
}

pub fn string_from_path(path: &Path) -> Option<String> {
    let path_os_str = path.as_os_str();
    if let Some(path_str) = path_os_str.to_str() {
        Some(path_str.to_string())
    } else {
        None
    }
}

pub struct TempDir {
    pub uuid: Uuid,
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(temp_path: &Path) -> Self {
        let dir_uuid = Uuid::new_v4();
        let dir_path = temp_path.join(dir_uuid.to_string());
        Self {
            uuid: dir_uuid,
            path: dir_path,
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn create(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.path)
    }

    pub fn as_str(&self) -> String {
        string_from_path(&self.path).unwrap_or_else(|| "PATH_ERROR".to_string())
    }

    pub fn exists(&self) -> bool {
        path_exists(&self.path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.exists() {
            match std::fs::remove_dir_all(&self.path) {
                Ok(_) => {
                    // Temp dir was deleted!
                }
                Err(err) => {
                    panic!(
                        "Error occurred trying to delete temp dir! path: {:?} - {:?}",
                        self.path, err
                    );
                }
            }
        }
    }
}

pub struct TempFile {
    pub uuid: Uuid,
    pub path: PathBuf,
}

impl TempFile {
    pub fn new(temp_path: &Path) -> Self {
        let file_uuid = Uuid::new_v4();
        let file_path = temp_path.join(file_uuid.to_string());
        Self {
            uuid: file_uuid,
            path: file_path,
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn as_str(&self) -> String {
        string_from_path(&self.path).unwrap_or_else(|| "PATH_ERROR".to_string())
    }

    pub fn exists(&self) -> bool {
        path_exists(&self.path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.exists() {
            match std::fs::remove_file(&self.path) {
                Ok(_) => {
                    // Temp file was deleted!
                }
                Err(err) => {
                    panic!(
                        "Error occurred trying to delete temp file! path: {:?} - {:?}",
                        self.path, err
                    );
                }
            }
        }
    }
}

pub fn exe() -> io::Result<std::fs::File> {
    exe_path().and_then(std::fs::File::open)
}

/// Returns the path of the currently running executable. On Linux this is `/proc/self/exe`.
// https://stackoverflow.com/questions/1023306/finding-current-executables-path-without-proc-self-exe
pub fn exe_path() -> io::Result<std::path::PathBuf> {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        Ok(std::path::PathBuf::from("/proc/self/exe"))
    }
    #[cfg(any(target_os = "dragonfly"))]
    {
        Ok(std::path::PathBuf::from("/proc/curproc/file"))
    }
    #[cfg(any(target_os = "netbsd"))]
    {
        Ok(std::path::PathBuf::from("/proc/curproc/exe"))
    }
    #[cfg(any(target_os = "solaris"))]
    {
        Ok(std::path::PathBuf::from(format!(
            "/proc/{}/path/a.out",
            nix::unistd::getpid()
        ))) // or /proc/{}/object/a.out ?
    }
    #[cfg(not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "solaris"
    )))]
    {
        std::env::current_exe()
    }
}
