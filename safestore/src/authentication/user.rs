use uuid::Uuid;

#[derive(Debug)]
pub struct User {
    pub id: Uuid,
    pub name: Vec<u8>,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl User {
    pub fn factory() -> User {
        let name = User::random_name();
        let public_key = vec![1, 2, 3, 4, 5];
        let private_key = vec![6, 7, 8, 9, 0];
        User::new(name.clone().into_bytes(), public_key, private_key)
    }

    pub fn display_info(&self) -> String {
        format!("User ID: {}, Name: {}", self.id, String::from_utf8_lossy(&self.name))
    }

    
    fn random_name() -> String {
        // cryptographically secure random number generator ;)
        let index = rand::random::<usize>() % User::USERNAMES.len();
        User::USERNAMES[index].to_string()
    }
    
    fn new(name: Vec<u8>, public_key: Vec<u8>, private_key: Vec<u8>) -> User {
        User {
            id: Uuid::new_v4(),
            name,
            public_key,
            private_key,
        }
    }
    
    const USERNAMES: [&'static str; 3] = ["Alice", "Bob", "Charlie"];
}



