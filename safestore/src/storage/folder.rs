use super::file::File;
use crate::cryptography::cryptography;

#[derive(Debug)]
pub struct Folder {
    pub uid: Vec<u8>,
    pub name: Vec<u8>,
    pub owner: Vec<u8>,
    pub files: Vec<File>,
    pub folders: Vec<Folder>,
    pub signature: Vec<u8>,

    // Key value pairs of file uid and key used to encrypt the file
    pub file_keys: Vec<(Vec<u8>, Vec<u8>)>,
    pub folder_keys: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Folder {
    pub fn new(uid: Vec<u8>, name: Vec<u8>, owner: Vec<u8>) -> Folder {
        Folder {
            uid,
            name,
            owner,
            files: Vec::new(),
            folders: Vec::new(),
            signature: Vec::new(),
            file_keys: Vec::new(),
            folder_keys: Vec::new(),
        }
    }

    pub fn add_file(&mut self, file: File, key: Vec<u8>) {
        self.file_keys.push((file.uid.clone(), key));
        self.files.push(file);
    }

    pub fn add_folder(&mut self, folder: Folder, key: Vec<u8>) {
        self.folder_keys.push((folder.uid.clone(), key));
        self.folders.push(folder);
    }

    pub fn display(&self, level: usize) -> String {
        let indent = "│   ".repeat(level);
        let mut display = format!("{}├── Folder: {:?}\n", indent, String::from_utf8_lossy(&self.name));
        
        for (i, folder) in self.folders.iter().enumerate() {
            let is_last = i == self.folders.len() - 1 && self.files.is_empty();
            display.push_str(&folder.display_nested(level + 1, is_last));
        }
        
        for (i, file) in self.files.iter().enumerate() {
            let is_last = i == self.files.len() - 1;
            display.push_str(&file.display_nested(level + 1, is_last));
            display.push_str("\n");
        }

        display
    }

    pub fn display_nested(&self, level: usize, is_last: bool) -> String {
        let indent = "│   ".repeat(level - 1) + if is_last { "    " } else { "│   " };
        let mut display = format!("{}├── Folder: {:?}\n", indent, String::from_utf8_lossy(&self.name));

        for (i, folder) in self.folders.iter().enumerate() {
            let is_last = i == self.folders.len() - 1 && self.files.is_empty();
            display.push_str(&folder.display_nested(level + 1, is_last));
        }
        
        for (i, file) in self.files.iter().enumerate() {
            let is_last = i == self.files.len() - 1;
            display.push_str(&file.display_nested(level + 1, is_last));
            display.push_str("\n");
        }

        display
    }

    pub fn encrypt(&self, key: Vec<u8>) -> Folder {
        // We need to encrypt: name, owner, uid, files, folders
        let encrypted_name = cryptography::encrypt(&key, self.name.clone());
        let encrypted_owner = cryptography::encrypt(&key, self.owner.clone());
        let encrypted_uid = cryptography::encrypt(&key, self.uid.clone());

        let mut encrypted_files: Vec<File> = Vec::new();
        let mut encrypted_folders: Vec<Folder> = Vec::new();
        let mut encrypted_file_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut encrypted_folder_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        
        for &(ref uid, ref file_key) in &self.file_keys {
            // The file itself
            let file = self.files.iter().find(|file| file.uid == *uid).unwrap();
            let encrypted_file = file.encrypt(file_key.clone());
            let encrypted_uid = encrypted_file.uid.clone();
            encrypted_files.push(encrypted_file);

            // And its key
            let encrypted_file_key = cryptography::encrypt(&key, file_key.clone());
            encrypted_file_keys.push((encrypted_uid, encrypted_file_key));
        }

        for &(ref uid, ref folder_key) in &self.folder_keys {
            // The folder itself
            let folder = self.folders.iter().find(|folder| folder.uid == *uid).unwrap();
            let encrypted_folder = folder.encrypt(folder_key.clone());
            let encrypted_uid = encrypted_folder.uid.clone();
            encrypted_folders.push(encrypted_folder);

            // And its key
            let encrypted_folder_key = cryptography::encrypt(&key, folder_key.clone());
            encrypted_folder_keys.push((encrypted_uid, encrypted_folder_key));
        }

        Folder {
            uid: encrypted_uid,
            name: encrypted_name,
            owner: encrypted_owner,
            files: encrypted_files,
            folders: encrypted_folders,
            signature: self.signature.clone(),
            file_keys: encrypted_file_keys,
            folder_keys: encrypted_folder_keys,
        }
    }

    pub fn decrypt(&self, key: Vec<u8>) -> Folder {
        // We need to decrypt: name, owner, uid, files, folders
        let decrypted_name = cryptography::decrypt(&key, self.name.clone());
        let decrypted_owner = cryptography::decrypt(&key, self.owner.clone());
        let decrypted_uid = cryptography::decrypt(&key, self.uid.clone());

        let mut decrypted_files: Vec<File> = Vec::new();
        let mut decrypted_folders: Vec<Folder> = Vec::new();
        let mut decrypted_file_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut decrypted_folder_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        
        for enc_file in &self.files {
            // First we get the encrypted file key
            let (_file_uid, file_key) = self.file_keys.iter().find(|(uid, _)| uid == &enc_file.uid).unwrap();
            let decrypted_file_key = cryptography::decrypt(&key, file_key.clone());
            
            // Then we decrypt the file
            let decrypted_file = enc_file.decrypt(decrypted_file_key.clone());
            let decrypted_uid = decrypted_file.uid.clone();
            decrypted_files.push(decrypted_file);
            decrypted_file_keys.push((decrypted_uid, decrypted_file_key));

        }

        for enc_folder in &self.folders {
            // First we get the encrypted folder key
            let (_folder_uid, folder_key) = self.folder_keys.iter().find(|(uid, _)| uid == &enc_folder.uid).unwrap();
            let decrypted_folder_key = cryptography::decrypt(&key, folder_key.clone());
            
            // Then we decrypt the folder
            let decrypted_folder = enc_folder.decrypt(decrypted_folder_key.clone());
            let decrypted_uid = decrypted_folder.uid.clone();
            decrypted_folders.push(decrypted_folder);
            decrypted_folder_keys.push((decrypted_uid, decrypted_folder_key));
        }

        Folder {
            uid: decrypted_uid,
            name: decrypted_name,
            owner: decrypted_owner,
            files: decrypted_files,
            folders: decrypted_folders,
            signature: self.signature.clone(),
            file_keys: decrypted_file_keys,
            folder_keys: decrypted_folder_keys,
        }
    }

}
