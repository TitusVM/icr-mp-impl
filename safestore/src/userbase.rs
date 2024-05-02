pub mod user;

use user::User;

pub struct Userbase {
    pub users: Vec<User>,
}

impl Userbase {
    pub fn new() -> Userbase {
        Userbase {
            users: Vec::new(),
        }
    }

    pub fn new_user(&mut self, username: String) {
        let id = self.users.len() as i32 + 1;
        let user = User::new(id, username);
        self.users.push(user);
    }
}