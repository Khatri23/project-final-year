use std::{io::{Read},net::{TcpListener,TcpStream}};
use serde::{Serialize,Deserialize};
#[derive(Serialize,Deserialize)]
struct Cipher{
    a:Vec<i32>,
    b:Vec<i32>,
}

fn handle_client(mut stream: TcpStream) {
     loop {
        // read message length
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(_) => {
                println!("Client disconnected");
                break;
            }
        }
        let len = u32::from_be_bytes(len_buf);
        // read actual message
        let mut buffer = vec![0u8; len as usize];
        stream.read_exact(&mut buffer).unwrap();

        // deserialize ONE message
        let data: Cipher = bincode::deserialize(&buffer).unwrap();

        println!("a: {:?}\nb: {:?}", data.a,data.b);
    }
}
fn main() {
    let listener=TcpListener::bind("127.0.0.1:7878").expect("Failed to bind 7878");
    println!("Server Running....");
    let mut i: u32=1;
    for stream in listener.incoming() {
        println!("Phase: {}",i);
        match stream {
            Ok(stream) => handle_client(stream),
            Err(e)=>println!("Something wrong {}",e),
        };
        i+=1;
    }
}
