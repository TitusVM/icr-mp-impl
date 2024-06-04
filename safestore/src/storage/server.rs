use std::io::SeekFrom;

use super::folder::Folder;
use crate::authentication::user::User;
use crate::cryptography::cryptography::hash_password;

use argon2::password_hash::SaltString;
use dryoc::types::ByteArray;
use uuid::Uuid;

#[derive(Debug)]
pub struct Server {
    // each user has a root folder that contains all their files and folders
    // this is essentially the / of the server (we are pretending the server is just a filesystem no OS or anything)
    // there are no files in the root folder
    pub root_folders: Vec<Folder>,
    pub enc_master_keys: Vec<(Vec<u8>, Vec<u8>)>, // (user_id (also the name of the root folder for that user), enc_master_key)
    // This contains the user, a salt value that needs to be used to create the challenge hash which will be used to authenticate the user
    pub users: Vec<(User, SaltString, Vec<u8>)>,
}

impl Server {
    pub fn new() -> Server {
        Server {
            root_folders: Vec::new(),
            enc_master_keys: Vec::new(),
            users: Vec::new(),
        }
    }

    pub fn login(&self, username: Vec<u8>, given_hash: Vec<u8>) -> (Folder, Vec<u8>) {
        // Preventing timing attacks
        let mut _valid = false;
        let user_id = self.get_uid_from_name(username);
        
        _valid = self.users.iter().any(|(u, _, _)| u.id == user_id);
        _valid = self.users.iter().any(|(u, challenge_salt, challenge_hash)| {
            if u.id == user_id {
                let (hash, _) = hash_password(given_hash.clone(), Some(challenge_salt));
                return hash == challenge_hash.clone();
            } 
            return false;
        });
        if _valid {
            println!("User login successful");
            // folder names are id of user whos folder it is
            let mut enc_master_key = Vec::new();
            for (folder_name, key) in &self.enc_master_keys {
                if Uuid::from_bytes(*folder_name.as_array()) == user_id {
                    enc_master_key = key.to_vec();
                    break;
                }
            }
            let root_folder: &Folder = self.root_folders.iter().find(|folder| folder.name == user_id.as_bytes()).unwrap();
            return (root_folder.clone(), enc_master_key.clone());
        } else {
            panic!("User login failed");
        }
    }

    pub fn change_password(&self, username: Vec<u8>, given_hash: Vec<u8>) {
        
    }

    pub fn add_user(&mut self, user: User, enc_master_key: Vec<u8>, challenge_salt: SaltString, challenge_hash: Vec<u8>, root_folder: Folder) {
        self.add_root_folder(root_folder, enc_master_key);
        self.users.push((user, challenge_salt, challenge_hash));
    }

    pub fn display_users(&self) {
        for (user, _, _) in &self.users {
            println!("{}", user.display_info());
        }
    }

    pub fn display_root_folders(&self) {
        for folder in &self.root_folders {
            println!("{}", folder.display(0));
        }
    }

    fn add_root_folder(&mut self, folder: Folder, enc_master_key: Vec<u8>) {
        let folder_name = folder.name.clone();
        self.root_folders.push(folder);
        self.enc_master_keys.push((folder_name, enc_master_key));
    }

    fn get_uid_from_name(&self, name: Vec<u8>) -> Uuid {
        self.users.iter().find(|(u, _, _)| u.name == name).unwrap().0.id
    }
}