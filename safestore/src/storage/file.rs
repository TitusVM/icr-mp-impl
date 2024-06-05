use dryoc::classic::crypto_box::PublicKey;
use dryoc::{classic::crypto_box::SecretKey, sign::SignedMessage};
use dryoc::types::StackByteArray;

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
    pub fn factory(owner: &Vec<u8>) -> File {
        let name = File::random_name();
        let data = File::random_content();
        File::new(name.into_bytes(), owner.clone(), data.into_bytes())
    }

    pub fn set_owner(&mut self, owner: Vec<u8>) {
        self.owner = owner;
    }

    pub fn display_nested(&self, level: usize, is_last: bool) -> String {
        let indent = "│   ".repeat(level - 1) + if is_last { "    " } else { "│   " };
        format!("{}├── File: name: {}, content: {}", indent, String::from_utf8_lossy(&self.name), String::from_utf8_lossy(&self.data))
    }

    pub fn symmetric_encrypt(&self, key: Vec<u8>) -> File {
        // We need to encrypt: name, data, owner
        let encrypted_name = cryptography::symmetric_encrypt(&key, self.name.clone());
        let encrypted_data = cryptography::symmetric_encrypt(&key, self.data.clone());
        let encrypted_owner = cryptography::symmetric_encrypt(&key, self.owner.clone());

        let encrypted_file = File::new(encrypted_name, encrypted_owner, encrypted_data);
        encrypted_file
    }

    pub fn symmetric_decrypt(&self, key: Vec<u8>) -> File {
        // We need to decrypt: name, data, owner
        let decrypted_name = cryptography::symmetric_decrypt(&key, self.name.clone());
        let decrypted_data = cryptography::symmetric_decrypt(&key, self.data.clone());
        let decrypted_owner = cryptography::symmetric_decrypt(&key, self.owner.clone());

        let decrypted_file = File::new(decrypted_name, decrypted_owner, decrypted_data);
        decrypted_file
    }

    pub fn asymmetric_encrypt(&self, receiver: (PublicKey, SecretKey), sender: (PublicKey, SecretKey)) -> File {
        // We need to encrypt: name, data, owner
        let encrypted_name = cryptography::asymmetric_encrypt(sender.1, receiver.0, self.name.clone());
        let encrypted_data = cryptography::asymmetric_encrypt(sender.1, receiver.0, self.data.clone());
        let encrypted_owner = cryptography::asymmetric_encrypt(sender.1, receiver.0, self.owner.clone());
        
        let encrypted_file = File::new(encrypted_name, encrypted_owner, encrypted_data);
        encrypted_file
    }

    pub fn asymmetric_decrypt(&self, receiver: (PublicKey, SecretKey), sender: (PublicKey, SecretKey)) -> File {
        // We need to decrypt: name, data, owner
        let decrypted_name = cryptography::asymmetric_decrypt(sender.0, receiver.1, self.name.clone());
        let decrypted_data = cryptography::asymmetric_decrypt(sender.0, receiver.1, self.data.clone());
        let decrypted_owner = cryptography::asymmetric_decrypt(sender.0, receiver.1, self.owner.clone());

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
        let signature = user.signing_keypair.sign_with_defaults(self.data.clone()).expect("Error signing");
        self.signature = signature.to_bytes();
    }

    pub fn verify(&self, user: &user::User) {
        let signature: SignedMessage<StackByteArray<64>, Vec<u8>> = SignedMessage::from_bytes(&self.signature).expect("Error parsing signature");
        signature
            .verify(&user.signing_keypair.public_key)
            .expect("Error verifying");
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.name);
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.data);
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    const FILE_CONTENTS: [&'static str; 3] = ["Hello, World!", "This is a file.", "This is a file too."];
    const FILE_NAMES: [&'static str; 3] = ["myfile", "anotherfile", "athirdfile"];

}