use core::panic;

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
    // This contains the user, the password salt, a salt value that needs to be used to create the challenge hash which will be used to authenticate the user
    pub users: Vec<(User, SaltString, SaltString, Vec<u8>)>,
}

impl Server {
    pub fn new() -> Server {
        Server {
            root_folders: Vec::new(),
            enc_master_keys: Vec::new(),
            users: Vec::new(),
        }
    }

    pub fn get_password_salt(&self, username: Vec<u8>) -> Option<SaltString> {
        let user_id = self.get_uid_from_name(&username);
        self.users.iter().find(|(u, _, _, _)| u.id == user_id.unwrap()).map(|(_, salt, _, _)| salt.clone())
    }

    pub fn login(&self, username: &Vec<u8>, given_hash: Vec<u8>) -> (Folder, Vec<u8>) {
        // Preventing timing attacks
        let mut _valid = false;
        let user_id = self.get_uid_from_name(username);
        
        _valid = self.users.iter().any(|(u, _, _, _)| u.id == user_id.unwrap());
        _valid = self.users.iter().any(|(u, _, _, challenge_hash)| {
            if u.id == user_id.unwrap() {
                return given_hash == challenge_hash.clone();
            }
            return false;
        });
        if _valid {
            println!("[SERVER] User login successful");
            // folder names are id of user whos folder it is
            let mut enc_master_key = Vec::new();
            for (folder_name, key) in &self.enc_master_keys {
                if Uuid::from_bytes(*folder_name.as_array()) == user_id.unwrap() {
                    enc_master_key = key.to_vec();
                    break;
                }
            }
            let root_folder: &Folder = self.root_folders.iter().find(|folder| folder.name == user_id.unwrap().as_bytes()).unwrap();
            return (root_folder.clone(), enc_master_key.clone());
        } else {
            // The wrong password was provided
            panic!("[SERVER] User login failed");
        }
    }

    pub fn logout(&mut self, username: Vec<u8>, enc_root_folder: Folder, enc_master_key: Vec<u8>, given_hash: Vec<u8>, new_challenge_hash: Option<Vec<u8>>, new_password_salt: Option<SaltString>) {
        let user_id = self.get_uid_from_name(&username).unwrap();
        let mut _valid = self.users.iter().any(|(u, _, _, _)| u.id == user_id);
        let mut _password_change = false;
        _valid = self.users.iter().any(|(u, _, challenge_salt, challenge_hash)| {
            if u.id == user_id {
                let (hash, _) = hash_password(given_hash.clone(), Some(challenge_salt));
                return hash == challenge_hash.clone();
            }
            return false;
        });
        if _valid {
            if !(new_challenge_hash.is_none() && new_password_salt.is_none()) {
                self.users.iter_mut().find(|(u, _, _, _)| u.id == user_id).map(|(_, password_salt, _, hash)| {
                    *password_salt = new_password_salt.clone().unwrap();
                    *hash = new_challenge_hash.clone().unwrap();

                });
                _password_change = true;
            } 
            self.root_folders.iter_mut().find(|folder| folder.name == user_id.as_bytes()).map(|folder| {
                *folder = enc_root_folder.clone();
            });
            self.enc_master_keys.iter_mut().find(|(name, _)| Uuid::from_bytes(*name.as_array()) == user_id).map(|(_, key)| {
                *key = enc_master_key.clone();
            });
            if _password_change {
                println!("[SERVER] User logout successful, password changed");
            } else {
                println!("[SERVER] User logout successful");
            }
        } else {
            // The wrong password was provided
            panic!("[SERVER] User logout failed");
        }
    }

    pub fn add_user(&mut self, user: User, enc_master_key: Vec<u8>, password_salt: SaltString, challenge_salt: SaltString, challenge_hash: Vec<u8>, root_folder: Folder) {
        self.add_root_folder(root_folder, enc_master_key);
        self.users.push((user, password_salt, challenge_salt, challenge_hash));
    }

    pub fn display_users(&self) {
        for (user, _, _, _) in &self.users {
            println!("{}", user.display_info());
        }
    }

    pub fn display_root_folders(&self) {
        for folder in &self.root_folders {
            println!("{}", folder.display(0));
            println!();
        }
    }

    pub fn get_user(&self, name: &Vec<u8>) -> Option<&User> {
        let uid = self.get_uid_from_name(name);
        self.users.iter().find(|(u, _, _, _)| u.id == uid.unwrap()).map(|(u, _, _, _)| u)
    }

    fn add_root_folder(&mut self, folder: Folder, enc_master_key: Vec<u8>) {
        let folder_name = folder.name.clone();
        self.root_folders.push(folder);
        self.enc_master_keys.push((folder_name, enc_master_key));
    }

    fn get_uid_from_name(&self, name: &Vec<u8>) -> Option<Uuid> {
        let user = self.users.iter().find(|(u, _, _, _)| u.name == *name);
        user.map(|(u, _, _, _)| u.id)
    }
}