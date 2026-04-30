
mod utility;
use egui::Ui;
use utility::{homomorphic_encryption,encode,decode};
use cxx::SharedPtr;
use std::{ io::{Read,Write}, net::TcpStream};
use crate::utility::homomorphic_encryption::{Cipher, Original_parameter, RLWE_DecryptOP, RLWE_DecryptRP, RLWE_EncryptOP, RLWE_EncryptRP, Rescale_parameter};
fn send<T:serde::Serialize>(stream:&mut TcpStream,msg:&T) {
   let data=bincode::serialize(&msg).unwrap();
   let len= data.len() as u32;
   stream.write_all(&len.to_be_bytes()).unwrap(); //send the length first
   //then send actual data
   stream.write_all(&data).unwrap();
}
fn main()->Result<(),eframe::Error> {
   let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Hello world",
        options,
        Box::new(|_cc| Box::new(MyApp::new())),
    )
}

use eframe::egui;
#[derive(PartialEq)]
enum Mode {
    CTCTADD, PTCTADD,SCMUL,
}
impl Default for Mode {
   fn default() -> Self {
      Mode::CTCTADD
   }
}
struct MyApp {
   input:String, //for message
   message:Vec<i32>, //include parse message
   mode:Mode,
   pt:String,
   data_from_server:Option<Cipher>,
   secret_key:Vec<i32>,
   op:SharedPtr<Original_parameter>,
   rp:SharedPtr<Rescale_parameter>,
   cipher:Vec<Cipher>,
   poly:Vec<Vec<i32>>, //message polynomial
   content:u8,// defines the byte value about the control instruction 
   //MSB 1, rp, first 3 bit set=mod switch , second 4 bit are for operation 
}
impl eframe::App for MyApp{
   fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
      egui::CentralPanel::default().show(ctx, |ui|{
         ui.heading("RLWE Homomorphic Encryption");
         ui.separator();
         self.render_app(ui);
         let pt=match self.mode {
            Mode::CTCTADD=>0,
            _=> {
               ui.label("Data");
               ui.text_edit_singleline(&mut self.pt);
               self.pt.trim().parse().unwrap_or(30)
            },
         };
         ui.horizontal(|ui|{
            if ui.button("Encrypt-3329").clicked() {
               self.content=self.content & 0x7f; //reset the msb
               self.cipher.clear();
               self.encryption();
            } 
            if ui.button("Encrypt-1697").clicked() {
               self.content=self.content | 0x80;//set the msb
               self.cipher.clear(); //remove all previously store value
               self.encryption();
            } 
            if ui.button("Decrypt").clicked() {
               self.decryption();
            }
            if ui.button("clear").clicked() { //warning after decryption, use clear
              self.clear();
            }
         }); 
         self.data_from_server =if ui.button("Initiate").clicked() {
            Some(self.server(&pt)) 
         }else{
            match &self.data_from_server{
               Some(data)=>{
                  Some(Cipher { a: data.a.clone(), b: data.b.clone() })
               }
               None=>None,
            }
         };
         match &self.data_from_server {
            Some(data)=>{
               ui.vertical(|ui|{
                  ui.separator();
                  ui.label("Result ciphertext");
                  ui.separator();
                  ui.label(format!("a: {:?}",data.a));
                  ui.label(format!("b: {:?}",data.b));
                  ui.separator();
                  let item=if self.content & 0x80 == 0x80 {
                        RLWE_DecryptRP(&self.secret_key, &data, &self.rp)
                     } else{
                        RLWE_DecryptOP(&self.secret_key, &data, &self.op)
                     };
                  ui.label(format!("poly: {:?}",item));
                  ui.label(format!("output: {}",decode(&item)));
               });
            }
            None =>(),
         };
         egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui|{
            ui.vertical(|ui|{
               for item in &self.poly {
                  ui.separator();
                  ui.label(format!("poly: {:?}",item));
                  ui.label(format!("message: {}",decode(item)));
               }
            });
         });       
      });
   }
}



impl MyApp {
   fn encryption(&mut self) {
      if self.message.is_empty() {
         println!("No message");
         return;
      }
      for item in &self.message {
         let temp=if  self.content & 0x80 != 0x80{
            RLWE_EncryptOP(&self.secret_key,
            encode(item, self.op.get_prime(), self.op.get_degree() as usize),
            &self.op)
         }else{
            RLWE_EncryptRP(&self.secret_key,
            encode(item, self.rp.get_prime(), self.rp.get_degree() as usize),
            &self.rp)
         };
         self.cipher.push(temp);
      }
   }

   fn decryption(&mut self) {
      if self.cipher.is_empty(){
         println!("No ciphertext to decrypt");
         return;
      }
      for item in &self.cipher {
         let data= if self.content & 0x80 != 0x80 {
            RLWE_DecryptOP(&self.secret_key, item, &self.op)
         } else {
            RLWE_DecryptRP(&self.secret_key, item, &self.rp)
         };
         self.poly.push(data);       
      }
   }

   fn server(&mut self,pt:&i32)->Cipher { //ciphertext and content
      self.content=self.content & 0xF0; // clear the lower bit to eliminate inconsistency
      self.content= self.content | match self.mode {
         Mode::CTCTADD =>  0b00000001,
         Mode::PTCTADD =>  0b00000010,
         Mode::SCMUL =>  0b00000100,
      };
      let mut stream:TcpStream=TcpStream::connect("127.0.0.1:7878").expect("Failed to connect");
      stream.write_all(&self.content.to_be_bytes()).unwrap();
      if *pt!=0{
         stream.write_all(&pt.to_be_bytes()).unwrap();
      }
      for item in &self.cipher {
         send(&mut stream, item);
      }  
      stream.shutdown(std::net::Shutdown::Write).unwrap();
      let mut buffer=Vec::new();
      stream.read_to_end(&mut buffer).expect("Error to get data");
      let cipher:Cipher=bincode::deserialize(&buffer).unwrap();
      cipher
}

}
//just the internal function used by MyApp
impl MyApp {
   fn new()->Self {
      Self { 
         input:String::new(),
         message:Vec::new(),
         mode:Mode::default(),
         op:homomorphic_encryption::initOP(),
         rp:homomorphic_encryption::initRP(),
         secret_key :vec![1 ,0 ,1 ,0 ,1 ,1 ,0 ,0 ,1 ,0 ,1 ,0 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,1 ,0 ,1 ,0 ,0 ,0 ,0 ,1 ,0 ,1 ,0 ,1],
         cipher:Vec::new(),
         poly:Vec::new(),
         content:0u8,
         data_from_server:None,
         pt:String::new(),
      }
   }
   fn clear(&mut self){
      self.cipher.clear();
      self.input.clear();
      self.message.clear();
      self.mode=Mode::default();
      self.poly.clear();
      self.content=0u8;
      self.data_from_server=None;
      self.pt.clear();
   }

   fn render_app(&mut self,ui: &mut Ui) {
      ui.vertical(|ui|{
         ui.horizontal(|ui| {
            ui.label("ADD Item:");
            ui.text_edit_singleline(&mut self.input);
            if ui.button("add").clicked() {
               if !self.input.is_empty() {
                  match self.input.trim().parse(){
                     Ok(m) => self.message.push(m),
                     Err(_)=>print!("only integer!"),
                  }
                  self.input.clear();
               }
            }
            if ui.button("remove").clicked() {
               if !self.message.is_empty() {
                  self.message.pop();
               }
               if !self.cipher.is_empty(){
                  self.cipher.pop();
               }
            }
            });
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui|{
               for (i,item) in self.message.iter().enumerate() {
                  ui.separator();
                  ui.label(format!("message{}: {}",i+1,item));
                  if i < self.cipher.len() {
                     ui.vertical(|ui|{
                        ui.label(format!("a: {:?}",self.cipher[i].a));
                        ui.label(format!("b:{:?}",self.cipher[i].b));
                     });//size of message vector and cipher are same
                  }
               }
            });
            
      });
      ui.separator();
      ui.label("Select Mode:");
      ui.horizontal(|ui| {
         ui.radio_value(&mut self.mode, Mode::CTCTADD, "CT-CT add");
         ui.radio_value(&mut self.mode, Mode::PTCTADD, "CT-PT add");
         ui.radio_value(&mut self.mode, Mode::SCMUL, "MUL");
      });      
      ui.separator();
   }
   
}