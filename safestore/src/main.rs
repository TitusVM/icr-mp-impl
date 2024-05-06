pub mod userbase;
pub mod storagebase;

// use userbase::Userbase;
use storagebase::StorageBase;
use storagebase::folder::Folder;
use storagebase::file::File;

fn main() {
    // let mut user_base = Userbase::new();
    // user_base.new_user("Alice".to_string());
    // user_base.new_user("Bob".to_string());
    // user_base.new_user("Mallory".to_string());
    // user_base.new_user("Trent".to_string());
    // user_base.new_user("Eve".to_string());
    // for user in user_base.users {
    //     println!("{}: {}", user.id, user.username);
    // }

    let mut storage_base = StorageBase::new();
    let mut root_folder = Folder::new(vec![0], "root".to_string(), 0);
    
    

}

