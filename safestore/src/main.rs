mod authentication;
mod storage;
mod cryptography;

use storage::file::File;
use storage::folder::Folder;
use authentication::user::User;
use cryptography::cryptography::get_random_key;


fn main() {
    let user = User::factory();
    let file1 = File::factory();
    let file2 = File::factory();
    let file3 = File::factory();

    println!("Our first user: {}", user.display_info());

    let mut folder1 = Folder::new(vec![7, 8, 9], "folder1".as_bytes().to_vec(), user.id.as_bytes().to_vec());
    
    let key1 = get_random_key().unwrap();
    let key2 = get_random_key().unwrap();

    folder1.add_file(file1, key1.to_vec());
    folder1.add_file(file2, key2.to_vec());

    let key3 = get_random_key().unwrap();

    let mut folder2 = Folder::new(vec![10, 11, 12], "folder2".as_bytes().to_vec(), user.id.as_bytes().to_vec());
    
    let key4 = get_random_key().unwrap();

    folder2.add_file(file3, key3.to_vec());
    folder2.add_folder(folder1, key4.to_vec());

    println!("{}", folder2.display(0));

    let master_key = get_random_key().unwrap();

    let encrypted_folder = folder2.encrypt(master_key.to_vec());

    println!("{}", encrypted_folder.display(0));

    let decrypted_folder = encrypted_folder.decrypt(master_key.to_vec());

    println!("{}", decrypted_folder.display(0));
}

