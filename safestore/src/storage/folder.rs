use super::file::File;
use crate::cryptography::cryptography;
use crate::authentication::user;

use dryoc::sign::SignedMessage;
use dryoc::classic::crypto_box::*;
use dryoc::types::*;

#[derive(Debug)]
#[derive(Clone)]
pub struct Folder {
    pub name: Vec<u8>,
    pub owner: Vec<u8>,
    pub files: Vec<File>,
    pub folders: Vec<Folder>,
    pub signature: Vec<u8>,

    // Key value pairs of file name and key used to encrypt the file
    pub file_keys: Vec<(Vec<u8>, Vec<u8>)>,
    pub folder_keys: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Folder {

    pub fn new(name: Vec<u8>, owner: Vec<u8>) -> Folder {
        Folder {
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
        self.file_keys.push((file.name.clone(), key));
        self.files.push(file);
    }

    pub fn add_folder(&mut self, folder: Folder, key: Vec<u8>) {
        self.folder_keys.push((folder.name.clone(), key));
        self.folders.push(folder);
    }

    pub fn display(&self, level: usize) -> String {
        let indent = "│   ".repeat(level);
        let mut _display = String::new();
        if level == 0 {
            _display = format!("{}├── Root folder owned by: {:?}\n", indent, String::from_utf8_lossy(&self.owner));
        } else {
            _display = format!("{}├── Folder: {} Owned by: {:?}\n", indent, String::from_utf8_lossy(&self.name), String::from_utf8_lossy(&self.owner));
        }
        
        for (i, folder) in self.folders.iter().enumerate() {
            let is_last = i == self.folders.len() - 1 && self.files.is_empty();
            _display.push_str(&folder.display_nested(level + 1, is_last));
        }
        
        for (i, file) in self.files.iter().enumerate() {
            let is_last = i == self.files.len() - 1;
            _display.push_str(&file.display_nested(level + 1, is_last));
            _display.push_str("\n");
        }

        _display
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

    pub fn symmetric_encrypt(&self, key: Vec<u8>, is_root: bool) -> Folder {
        // We need to encrypt: name, owner, uid, files, folders
        let mut _encrypted_name = Vec::new();
        if !is_root {
            _encrypted_name = cryptography::symmetric_encrypt(&key, self.name.clone());
        } else {
            _encrypted_name = self.name.clone();
        }
        let encrypted_owner = cryptography::symmetric_encrypt(&key, self.owner.clone());

        let mut encrypted_files: Vec<File> = Vec::new();
        let mut encrypted_folders: Vec<Folder> = Vec::new();
        let mut encrypted_file_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut encrypted_folder_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        
        for &(ref name, ref file_key) in &self.file_keys {
            // The file itself
            let file = self.files.iter().find(|file| file.name == *name).unwrap();
            let encrypted_file = file.symmetric_encrypt(file_key.clone());
            let encrypted_name = encrypted_file.name.clone();
            encrypted_files.push(encrypted_file);

            // And its key
            let encrypted_file_key = cryptography::symmetric_encrypt(&key, file_key.clone());
            encrypted_file_keys.push((encrypted_name, encrypted_file_key));
        }

        for &(ref name, ref folder_key) in &self.folder_keys {
            // The folder itself
            let folder = self.folders.iter().find(|folder| folder.name == *name).unwrap();
            let encrypted_folder = folder.symmetric_encrypt(folder_key.clone(), false);
            let encrypted_name = encrypted_folder.name.clone();
            encrypted_folders.push(encrypted_folder);

            // And its key
            let encrypted_folder_key = cryptography::symmetric_encrypt(&key, folder_key.clone());
            encrypted_folder_keys.push((encrypted_name, encrypted_folder_key));
        }

        Folder {
            name: _encrypted_name,
            owner: encrypted_owner,
            files: encrypted_files,
            folders: encrypted_folders,
            signature: self.signature.clone(),
            file_keys: encrypted_file_keys,
            folder_keys: encrypted_folder_keys,
        }
    }

    pub fn symmetric_decrypt(&self, key: Vec<u8>, is_root: bool) -> Folder {
        // We need to decrypt: name, owner, uid, files, folders
        let mut _decrypted_name = Vec::new();
        if !is_root {
            _decrypted_name = cryptography::symmetric_decrypt(&key, self.name.clone());
        } else {
            _decrypted_name = self.name.clone();
        }
        let decrypted_owner = cryptography::symmetric_decrypt(&key, self.owner.clone());

        let mut decrypted_files: Vec<File> = Vec::new();
        let mut decrypted_folders: Vec<Folder> = Vec::new();
        let mut decrypted_file_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut decrypted_folder_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        
        for enc_file in &self.files {
            // First we get the encrypted file key
            let (_file_name, file_key) = self.file_keys.iter().find(|(uid, _)| uid == &enc_file.name).unwrap();
            let decrypted_file_key = cryptography::symmetric_decrypt(&key, file_key.clone());
            
            // Then we decrypt the file
            let decrypted_file = enc_file.symmetric_decrypt(decrypted_file_key.clone());
            let decrypted_name = decrypted_file.name.clone();
            decrypted_files.push(decrypted_file);
            decrypted_file_keys.push((decrypted_name, decrypted_file_key));

        }

        for enc_folder in &self.folders {
            // First we get the encrypted folder key
            let (_folder_uid, folder_key) = self.folder_keys.iter().find(|(uid, _)| uid == &enc_folder.name).unwrap();
            let decrypted_folder_key = cryptography::symmetric_decrypt(&key, folder_key.clone());
            
            // Then we decrypt the folder
            let decrypted_folder = enc_folder.symmetric_decrypt(decrypted_folder_key.clone(), false);
            let decrypted_name = decrypted_folder.name.clone();
            decrypted_folders.push(decrypted_folder);
            decrypted_folder_keys.push((decrypted_name, decrypted_folder_key));
        }

        Folder {
            name: _decrypted_name,
            owner: decrypted_owner,
            files: decrypted_files,
            folders: decrypted_folders,
            signature: self.signature.clone(),
            file_keys: decrypted_file_keys,
            folder_keys: decrypted_folder_keys,
        }
    }

    pub fn asymmetric_encrypt(&self, receiver: (PublicKey, SecretKey), sender: (PublicKey, SecretKey)) -> Folder {
        // We need to encrypt: name, owner, uid, files, folders
        // The function will return ciphertexts and nonces for each encryption
        let encrypted_name = cryptography::asymmetric_encrypt(sender.1, receiver.0, self.name.clone());
        let encrypted_owner = cryptography::asymmetric_encrypt(sender.1, receiver.0, self.owner.clone());
        let mut encrypted_files: Vec<File> = Vec::new();
        let mut encrypted_folders: Vec<Folder> = Vec::new();
        let mut encrypted_file_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut encrypted_folder_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        for &(ref name, ref file_key) in &self.file_keys {
            // The file itself
            let file = self.files.iter().find(|file| file.name == *name).unwrap();
            let encrypted_file = file.asymmetric_encrypt(receiver, sender);
            let encrypted_name = encrypted_file.name.clone();
            encrypted_files.push(encrypted_file);

            // And its key
            let encrypted_file_key = cryptography::asymmetric_encrypt(sender.1, receiver.0, file_key.clone());
            encrypted_file_keys.push((encrypted_name, encrypted_file_key));
        }

        for &(ref name, ref folder_key) in &self.folder_keys {
            // The folder itself
            let folder = self.folders.iter().find(|folder| folder.name == *name).unwrap();
            let encrypted_folder = folder.asymmetric_encrypt(receiver, sender);
            let encrypted_name = encrypted_folder.name.clone();
            encrypted_folders.push(encrypted_folder);

            // And its key
            let encrypted_folder_key = cryptography::asymmetric_encrypt(sender.1, receiver.0, folder_key.clone());
            encrypted_folder_keys.push((encrypted_name, encrypted_folder_key));
        }

        Folder {
            name: encrypted_name,
            owner: encrypted_owner,
            files: encrypted_files,
            folders: encrypted_folders,
            signature: self.signature.clone(),
            file_keys: encrypted_file_keys,
            folder_keys: encrypted_folder_keys,
        }
    }

    pub fn asymmetric_decrypt(&self, receiver: (PublicKey, SecretKey), sender: (PublicKey, SecretKey)) -> Folder {
        // We need to decrypt: name, owner, uid, files, folders
        let mut decrypted_files: Vec<File> = Vec::new();
        let mut decrypted_folders: Vec<Folder> = Vec::new();
        let mut decrypted_file_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut decrypted_folder_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        let decrypted_name = cryptography::asymmetric_decrypt(sender.0, receiver.1, self.name.clone());
        let decrypted_owner = cryptography::asymmetric_decrypt(sender.0, receiver.1, self.owner.clone());

        for enc_file in &self.files {
            // First we get the encrypted file key
            let (_file_name, file_key) = self.file_keys.iter().find(|(uid, _)| uid == &enc_file.name).unwrap();
            let decrypted_file_key = cryptography::asymmetric_decrypt(sender.0, receiver.1, file_key.clone());
            
            // Then we decrypt the file
            let decrypted_file = enc_file.asymmetric_decrypt(sender, receiver);
            let decrypted_name = decrypted_file.name.clone();
            decrypted_files.push(decrypted_file);
            decrypted_file_keys.push((decrypted_name, decrypted_file_key));

        }

        for enc_folder in &self.folders {
            // First we get the encrypted folder key
            let (_folder_uid, folder_key) = self.folder_keys.iter().find(|(uid, _)| uid == &enc_folder.name).unwrap();
            let decrypted_folder_key = cryptography::asymmetric_decrypt(sender.0, receiver.1, folder_key.clone());
            
            // Then we decrypt the folder
            let decrypted_folder = enc_folder.asymmetric_decrypt(sender, receiver);
            let decrypted_name = decrypted_folder.name.clone();
            decrypted_folders.push(decrypted_folder);
            decrypted_folder_keys.push((decrypted_name, decrypted_folder_key));
        }

        Folder {
            name: decrypted_name,
            owner: decrypted_owner,
            files: decrypted_files,
            folders: decrypted_folders,
            signature: self.signature.clone(),
            file_keys: decrypted_file_keys,
            folder_keys: decrypted_folder_keys,
        }
    }

    pub fn sign(&mut self, user: &user::User) {
        let signature = user.signing_keypair.sign_with_defaults(self.to_bytes()).expect("Error signing");
        self.signature = signature.to_bytes();
    }

    pub fn verify(&self, user: &user::User) -> bool {
        let computed_signature = user.signing_keypair.sign_with_defaults(self.to_bytes()).expect("Error signing");
        let signature: SignedMessage<StackByteArray<64>, Vec<u8>> = SignedMessage::from_bytes(&self.signature).expect("Error parsing signature");
        if signature.verify(&user.signing_keypair.public_key).is_err() {
            return false;
        }
        computed_signature == signature
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.name);
        bytes.extend_from_slice(&self.owner);

        for file in &self.files {
            bytes.extend_from_slice(&file.to_bytes());
        }

        for folder in &self.folders {
            bytes.extend_from_slice(&folder.to_bytes());
        }

        bytes
    }
}
