use uuid::Uuid;
use dryoc::sign::SigningKeyPair;
use dryoc::types::StackByteArray;
use dryoc::dryocbox::KeyPair;


#[derive(Debug)]
pub struct User {
    pub id: Uuid,
    pub name: Vec<u8>,
    pub signing_keypair: SigningKeyPair<StackByteArray<32>, StackByteArray<64>>,
    pub keypair: KeyPair,
}

impl User {
    pub fn factory() -> User {
        let name = User::random_name();
        let public_key = vec![1, 2, 3, 4, 5];
        let private_key = vec![6, 7, 8, 9, 0];
        User::new(name.clone().into_bytes())
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
            keypair: KeyPair::gen(),
        }
    }
    
    const USERNAMES: [&'static str; 16] = ["Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy", "Mallory", "Oscar", "Peggy", "Romeo", "Trent", "Walter"];
}



