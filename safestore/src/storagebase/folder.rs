use super::file::File;

#[derive(Debug)]
pub struct Folder {
    pub uid: Vec<i32>,
    pub name: String,
    pub owner: i32,
    pub files: Vec<File>,
    pub folders: Vec<Folder>,
}

impl Folder {
    pub fn new(uid: Vec<i32>, name: String, owner: i32) -> Folder {
        Folder {
            uid,
            name,
            owner,
            files: Vec::new(),
            folders: Vec::new(),
        }
    }

    pub fn add_file(&mut self, file: File) {
        self.files.push(file);
    }
}
