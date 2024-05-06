pub mod file;
pub mod folder;

use file::File;
use folder::Folder;

pub struct StorageBase {
    pub files: Vec<File>,
    pub folders: Vec<Folder>,
}

impl StorageBase {
    pub fn new() -> StorageBase {
        StorageBase {
            files: Vec::new(),
            folders: Vec::new(),
        }
    }

    pub fn add_file_to_folder(&mut self, file: File, folder: &mut Folder) {
        folder.add_file(file);
    }
}