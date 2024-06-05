use uuid::Uuid;
use dryoc::sign::SigningKeyPair;
use dryoc::types::StackByteArray;
use dryoc::classic::crypto_box::*;


#[derive(Debug)]
pub struct User {
    pub id: Uuid,
    pub name: Vec<u8>,
    pub signing_keypair: SigningKeyPair<StackByteArray<32>, StackByteArray<64>>,
    pub keypair: (PublicKey, SecretKey),
}

impl User {
    pub fn factory(name: Option<Vec<u8>>) -> User {
        let name = match name {
            Some(n) => n,
            None => User::random_name().into_bytes(),
        };
        User::new(name)
    }

    pub fn display_info(&self) -> String {
        format!("User ID: {}, Name: {}", self.id, String::from_utf8_lossy(&self.name))
    }

    
    fn random_name() -> String {
        // cryptographically secure random number generator ;)
        let index = rand::random::<usize>() % User::USERNAMES.len();
        User::USERNAMES[index].to_string()
    }
    
    fn new(name: Vec<u8>) -> User {
        User {
            id: Uuid::new_v4(),
            name,
            signing_keypair: SigningKeyPair::gen_with_defaults(),
            keypair: crypto_box_keypair(),
        }
    }
    
    const USERNAMES: [&'static str; 16] = ["Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy", "Mallory", "Oscar", "Peggy", "Romeo", "Trent", "Walter"];
}



