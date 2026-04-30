use std::{io::{Read, Write},net::{TcpListener,TcpStream}};
use serde::{Serialize,Deserialize};
#[derive(Serialize,Deserialize)]
struct Cipher{
    a:Vec<i32>,
    b:Vec<i32>,
}
const DEGREE:usize=32;
const PRIME_OP:i32=3329;
const PRIME_RP:i32=1697;

fn handle_client(mut stream: TcpStream) {
    let mut ciphers:Vec<Cipher>=Vec::new();
    let mut content=[0u8;1];
    stream.read_exact(&mut content).expect("failed to fetch content");
    let content=u8::from_be_bytes(content); //first retrive content
    let  plaintext =if content & 2 ==2 || content & 4 == 4 {
        let mut plaintext=[0u8;4];
        stream.read_exact(&mut plaintext).expect("Failed to fetch");
        i32::from_be_bytes(plaintext)
    } else {
        0
    };
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
        ciphers.push(data);
    } //do something with message
    println!("Content={content} PT= {plaintext}");
    for item in &ciphers {
        println!("{:?}",item.a);
        println!("{:?}\n",item.b);
    }
    let data= match content {
        1 => polynomial_addition(&ciphers, &PRIME_OP),
        129 => polynomial_addition(&ciphers, &PRIME_RP), //normal
        2 => plaintext_addition(&ciphers, &PRIME_OP, plaintext),
        130 => plaintext_addition(&ciphers, &PRIME_RP, plaintext),
        4 => scalar_multiplication(&ciphers, &PRIME_OP, plaintext),
        132 =>scalar_multiplication(&ciphers, &PRIME_RP, plaintext),
        _ => polynomial_addition(&ciphers, &PRIME_OP),
    };
    
    println!("Result ciphertext\n{:?}\n{:?}",data.a,data.b);
    let byte=bincode::serialize(&data).unwrap();
    stream.write_all(&byte).unwrap();
} //server done for one connection.

fn main() {
    let listener=TcpListener::bind("127.0.0.1:7878").expect("Failed to bind 7878");
    println!("Server Running....");
    let mut i: u32=1;
    for stream in listener.incoming() {
        println!("Phase: {}",i);
        match stream {
            Ok(stream) => handle_client(stream),
            Err(e)=>println!("Halted {}",e),
        };
        println!("Server Listening.....");
        i+=1;
    }
}
fn scalar_multiplication(ciphers:&Vec<Cipher>,prime:&i32,value:i32) ->Cipher{
    let mut data = if ciphers.len() > 1 {
        polynomial_addition(ciphers, prime)
    } else {
        Cipher { a: ciphers[0].a.clone(), b: ciphers[0].b.clone() }
    };
    for i in 0..DEGREE {
        data.a[i]=(data.a[i] * value )%prime;
        data.b[i]=(data.b[i] * value) % prime;
    }
    data
}
fn plaintext_addition(ciphers:&Vec<Cipher>,prime:&i32,value:i32) ->Cipher {
    let msg=encode(value, prime);
    let data = if ciphers.len() > 1 {
        polynomial_addition(ciphers, prime)
    } else {
        Cipher { a: ciphers[0].a.clone(), b: ciphers[0].b.clone() }
    };
    let mut c2=vec![0;DEGREE];
    for i in 0..DEGREE {
        c2[i]=data.b[i]+msg[i];
        if c2[i] >= *prime {
            c2[i]-=prime;
        }
    }
    Cipher { a: data.a, b: c2 }
}
fn polynomial_addition(ciphers:&Vec<Cipher>,prime:&i32)-> Cipher {
    //add the polynomials
    let mut c1=vec![0;DEGREE];
    let mut c2=vec![0;DEGREE];
    for item in ciphers {
        for i in 0..DEGREE {
            c1[i]+= item.a[i];
            c2[i]+=item.b[i];
            if c1[i] >= *prime {
                c1[i]-=*prime;
            }
            if c2[i] >= *prime{
                c2[i]-=*prime;
            }
        }
    }
    Cipher { a:c1, b: c2 }
}
fn encode(msg: i32, prime:&i32) ->Vec<i32> {
    let t:i32=50;
    let sk:i32=prime/t;
    let mut message=vec![0;DEGREE];
    let mut i:usize=0;
    let mut m=msg;
    while i < DEGREE && m > 0 {
        message[i]= (m & 1) *sk;
        m =m >> 1;
        i+=1;
    }
    message
}
