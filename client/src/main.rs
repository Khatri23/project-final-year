use std::{io::{ Write},net::{self, TcpStream}};
mod utility;
use utility::{homomorphic_encryption,encode,decode};
fn main() {
   let mut stream:TcpStream=TcpStream::connect("127.0.0.1:7878").expect("Failed to connect");
   do_something(&mut stream);
   stream.shutdown(net::Shutdown::Write).unwrap();
}
fn do_something(stream:&mut TcpStream) {
      let op=homomorphic_encryption::initOP();
    let rp=homomorphic_encryption::initRP();
    rp.get_degree(); rp.get_prime();
    let secret=vec![1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1];
    let  msg:i32=7892415;
    let cipher=homomorphic_encryption::RLWE_EncryptOP(&secret, encode( &msg,op.get_prime(),op.get_degree() as usize),&op);
    println!("Encryption OP\n{:?} \n{:?}",cipher.a,cipher.b);
    let d=homomorphic_encryption::RLWE_DecryptOP(&secret, &cipher, &op);
    println!("Decryption OP\n{:?}",d);
    println!("{}",decode(d));
   send(stream,&cipher);
    let cipher=homomorphic_encryption::RLWE_EncryptRP(&secret, encode(&msg,rp.get_prime(),rp.get_degree() as usize), &rp);
    println!("Encryption RP\n{:?} \n{:?}",cipher.a,cipher.b);
    let d=homomorphic_encryption::RLWE_DecryptRP(&secret, &cipher, &rp);
    println!("Decryption RP\n{:?}",d);
    println!("{}",decode(d));
   send(stream,&cipher);

}

fn send<T:serde::Serialize>(stream:&mut TcpStream,msg:&T) {
   let data=bincode::serialize(&msg).unwrap();
   let len= data.len() as u32;
   stream.write_all(&len.to_be_bytes()).unwrap(); //send the length first
   //then send actual data
   stream.write_all(&data).unwrap();
}