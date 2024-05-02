#[derive(Debug)]
pub struct User {
    pub id: i32,
    pub username: String,
}

// User constructor
impl User {
    pub fn new(id: i32, username: String) -> User {
        User {
            id,
            username,
        }
    }
}