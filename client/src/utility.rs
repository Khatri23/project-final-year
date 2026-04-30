
use rand::{RngCore, rngs::OsRng,Rng};
//this bridges c++ & rust code
#[cxx::bridge]
pub mod homomorphic_encryption {
    #[derive(Serialize,Deserialize)]
    pub struct Cipher {
        pub a:Vec<i32>,
        pub b:Vec<i32>,
    }
    extern "Rust" {
        fn small_rand()->Vec<i32>; //returns binary array of size 32
        fn big_rand(p:i32,sz:i32) ->Vec<i32>; //returns random value from 1 to 3328
    }

    unsafe extern "C++" { //instructing compiler to give responsibility to me
        include!("client/include/RLWE.h");
        pub type Original_parameter; //opaque type so that its field are not visible to rust but can pass the type only by ref
        pub fn get_prime(self:&Original_parameter)->i32; //function signature should be same 
        pub fn get_degree(self:&Original_parameter)->i32;
        pub fn initOP()->SharedPtr<Original_parameter>;

        pub type Rescale_parameter;
        pub fn get_prime(self:&Rescale_parameter)->i32;
        pub fn get_degree(self:&Rescale_parameter)->i32;
        pub fn initRP()->SharedPtr<Rescale_parameter>;
        //for original parameter
       pub fn RLWE_EncryptOP(secret:&Vec<i32>,message:Vec<i32>,op: &SharedPtr<Original_parameter>) ->Cipher;
       pub fn RLWE_DecryptOP(secret:&Vec<i32>,cipher:&Cipher,op:&SharedPtr<Original_parameter>) ->Vec<i32>;
        //for rescaled parameter
       pub fn RLWE_EncryptRP(secret:&Vec<i32>,message:Vec<i32>,rp: &SharedPtr<Rescale_parameter>) ->Cipher;
       pub fn RLWE_DecryptRP(secret:&Vec<i32>,cipher:&Cipher,rp:&SharedPtr<Rescale_parameter>) ->Vec<i32>;
    }
}
fn small_rand() ->Vec<i32> {
    let mut rng=OsRng;
    let mut  random_u32=rng.next_u32();
    let mut ctx:Vec<i32>=Vec::new();
    ctx.resize(32, 0);
    let mut i:usize=0;
    while random_u32 > 0 {
        ctx[i]=(random_u32 & 1) as i32;
        random_u32=random_u32 >> 1;
        i+=1;
    }
    ctx
}
fn big_rand(p:i32,sz:i32)->Vec<i32> {
    let mut rng = rand::thread_rng();
    let mut ctx:Vec<i32>=Vec::new();
    ctx.resize(sz as usize, 0);
    for i in &mut ctx {
        *i+= rng.gen_range(0..p-1);
    }
    ctx
}

pub fn encode(msg:& i32, prime:i32,degree:usize) ->Vec<i32> {
    let t:i32=50;
    let sk:i32=prime/t;
    let mut message= Vec::new();
    message.resize(degree , 0);
    let mut i:usize=0;
    let mut m=*msg;
    while i < degree && m > 0 {
        message[i]= (m & 1) *sk;
        m =m >> 1;
        i+=1;
    }
    message
}
pub fn decode(msg:&Vec<i32>) ->u64 {
    let mut result:u64=0;
    for (_,i) in msg.iter().rev().enumerate() {
        result=(result << 1) + *i as u64;
    }
    result
}
