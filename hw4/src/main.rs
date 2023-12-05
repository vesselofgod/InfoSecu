use std::{env, fs};
use openssl::sign::{Signer, Verifier};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use std::io::prelude::*;
use std::process::Command;
use elf::ElfBytes;
use elf::endian::AnyEndian;


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        //Case 3 : invalid command
        println!("INVALID COMMAND\n");
        return;
    }
    let mut key="";
    let mut file_path="";
    let mode = &args[1];

    for i in 0..args.len()-1 {
        if args[i] == "-k" {
            key = &args[i+1];
        } 
        if args[i] == "-e" {
            file_path = &args[i+1]; 
        }
    }
    let file_data = std::fs::read(file_path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Open test1");
    let shdr = file.section_headers();

    let key = fs::read_to_string(key).unwrap();

    let output = format!("{}{}", file_path, "-signed");
    if mode == "sign" {

        let tmp = Rsa::private_key_from_pem(key.as_bytes()).expect("error");
        let pkey = PKey::from_rsa(tmp).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();

        for section in shdr.iter(){
            for s in section.iter(){
                if s.sh_flags==6 {
                    let offset: u64 = s.sh_offset;
                    let end: u64 = s.sh_offset + s.sh_size;
                    signer.update(&slice[offset as usize ..end as usize]).unwrap();

                }
            }
        }

        let signature = signer.sign_to_vec().unwrap();
        let mut sig_file = std::fs::File::create("sig_file").unwrap();
        match sig_file.write_all(&signature) {
            Ok(file) => file,
            Err(_) => {
            }
        };
        let _res = Command::new("objcopy")
        .args(&["--add-section", ".signature=sig_file"])
        .args(&["--set-section-flags", ".signature=contents,readonly"])
        .arg(file_path)
        .arg(output)
        .output();

    }


    if mode == "verify"{
        let signature = file.section_header_by_name(".signature").expect("msg");
        if signature == None {
            println!("NOT_SIGNED");
            return;
        }
        let start = signature.unwrap().sh_offset;
        let end = signature.unwrap().sh_offset + signature.unwrap().sh_size;
        let signature_data = &slice[start as usize ..end as usize];
    
        let tmp = Rsa::public_key_from_pem(key.as_bytes()).expect("error");
        let pkey = PKey::from_rsa(tmp).unwrap();

        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
    
        for section in shdr.iter(){
            for s in section.iter(){
                if s.sh_flags==6 {
                    let offset: u64 = s.sh_offset;
                    let end: u64 = s.sh_offset + s.sh_size;
                    verifier.update(&slice[offset as usize ..end as usize]).unwrap();

                }
            }
        }
    
        match verifier.verify(signature_data).unwrap() {
            true => println!("OK"),
            false => println!("NOT_OK"),
        }
    }
}