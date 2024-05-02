pub mod userbase;

use userbase::Userbase;

fn main() {
    let mut user_base = Userbase::new();
    user_base.new_user("Alice".to_string());
    user_base.new_user("Bob".to_string());
    user_base.new_user("Mallory".to_string());
    user_base.new_user("Trent".to_string());
    user_base.new_user("Eve".to_string());
    for user in user_base.users {
        println!("{}: {}", user.id, user.username);
    }
}

