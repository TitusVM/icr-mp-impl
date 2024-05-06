#[derive(Debug)]
pub struct File {
    pub uid: Vec<i32>,
    pub name: String,
    pub owner: i32,
    pub data: Vec<u8>,
}

impl File {
    pub fn new(uid: Vec<i32>, name: String, owner: i32, data: Vec<u8>) -> File {
        File {
            uid,
            name,
            owner,
            data,
        }
    }
}