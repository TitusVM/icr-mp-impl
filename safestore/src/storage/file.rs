use dryoc::sign::{SignedMessage, VecSignedMessage};
use dryoc::types::StackByteArray;
use dryoc::dryocbox::DryocBox;

use crate::{authentication::user, cryptography::cryptography};

#[derive(Debug)]
#[derive(Clone)]
pub struct File {
    pub name: Vec<u8>,
    pub owner: Vec<u8>,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl File {
    pub fn factory() -> File {
        let name = File::random_name();
        let owner = "Nobody".as_bytes().to_vec();
        let data = File::random_content();
        File::new(name.into_bytes(), owner, data.into_bytes())
    }

    pub fn set_owner(&mut self, owner: Vec<u8>) {
        self.owner = owner;
    }

    pub fn display_nested(&self, level: usize, is_last: bool) -> String {
        let indent = "│   ".repeat(level - 1) + if is_last { "    " } else { "│   " };
        format!("{}├── File: name: {}, content: {}", indent, String::from_utf8_lossy(&self.name), String::from_utf8_lossy(&self.data))
    }

    pub fn encrypt(&self, key: Vec<u8>) -> File {
        // We need to encrypt: name, data, owner, uid
        let encrypted_name = cryptography::encrypt(&key, self.name.clone());
        let encrypted_data = cryptography::encrypt(&key, self.data.clone());
        let encrypted_owner = cryptography::encrypt(&key, self.owner.clone());

        let encrypted_file = File::new(encrypted_name, encrypted_owner, encrypted_data);
        encrypted_file
    }

    pub fn decrypt(&self, key: Vec<u8>) -> File {
        // We need to decrypt: name, data, owner, uid
        let decrypted_name = cryptography::decrypt(&key, self.name.clone());
        let decrypted_data = cryptography::decrypt(&key, self.data.clone());
        let decrypted_owner = cryptography::decrypt(&key, self.owner.clone());

        let decrypted_file = File::new(decrypted_name, decrypted_owner, decrypted_data);
        decrypted_file
    }
    
    fn random_content() -> String {
        let index = rand::random::<usize>() % File::FILE_CONTENTS.len();
        File::FILE_CONTENTS[index].to_string()
    }

    fn random_name() -> String {
        let index = rand::random::<usize>() % File::FILE_NAMES.len();
        File::FILE_NAMES[index].to_string()
    }
    

    pub fn new(name: Vec<u8>, owner: Vec<u8>, data: Vec<u8>) -> File {
        File {
            name,
            owner,
            data,
            signature: Vec::new(),
        }
    }

    pub fn sign(&mut self, user: &user::User) {
        let signature = user.signing_keypair.sign_with_defaults(&*self.data).expect("Error signing");
        self.signature = signature.to_bytes();
    }

    pub fn verify(&self, user: &user::User) {
        let signature: SignedMessage<StackByteArray<64>, Vec<u8>> = SignedMessage::from_bytes(&self.signature).expect("Error parsing signature");
        signature
            .verify(&user.signing_keypair.public_key)
            .expect("Error verifying");
    }

    const FILE_CONTENTS: [&'static str; 3] = ["Hello, World!", "This is a file.", "This is a file too."];
    const FILE_NAMES: [&'static str; 3] = ["myfile", "anotherfile", "athirdfile"];

}