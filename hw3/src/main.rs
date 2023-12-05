use std::io::{Result, BufWriter, Write};
use openssl::symm::{encrypt, decrypt, Cipher};
use std::{env, fs};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use std::process;
use pbkdf2::{pbkdf2_hmac_array};
type HmacSha256 = Hmac<Sha256>;

fn write_hex<W: Write>(file: &mut BufWriter<W>, data: &[u8]) -> Result<()> {
    for val in data {
        write!(file, "{:02x}", val)?;
    }
    Ok(())
}

fn main() {

    let args: Vec<String> = env::args().collect();
    if args.len() != 10 {
        //Case 3 : invalid command
        println!("ERROR\n");
        process::exit(2);
    }
    let mut key="";
    let mut input_file="";
    let mut output_file="";
    let mut auth_tag="";
    let mode = &args[1];
    let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

    for i in 0..args.len()-1 {
        if args[i] == "-key" {
            key = &args[i+1];
        } 
        if args[i] == "-in" {
            input_file = &args[i+1]; 
        }
        if args[i] == "-out" {
            output_file = &args[i+1];
        }
        if args[i] == "-tag" {
            auth_tag = &args[i+1];
        }
    }

    let f: std::result::Result<String, std::io::Error> = fs::read_to_string(input_file);
    let infile_contents = match f {
        Ok(file) => file,
        Err(_) => {
            println!("ERROR\n");
            process::exit(2);
        }
    };
    let f = fs::read_to_string(key);
    let binding = match f {
        Ok(file) => file,
        Err(_) => {
            println!("ERROR\n");
            process::exit(2);
        }
    };
    let symkey = binding.as_bytes();

    let salt = b"salt";
    let key2 = pbkdf2_hmac_array::<Sha256, 32>(symkey, salt, 4096);


    let f = std::fs::File::create(output_file);
    let mut outfile = match f {
        Ok(file) => file,
        Err(_) => {
            println!("ERROR\n");
            process::exit(2);
        }
    };
    if mode == "enc" {
        //TODO
        let cipher = Cipher::aes_256_cbc();
        let f = std::fs::File::create(auth_tag);
        let tagfile = match f {
            Ok(file) => file,
            Err(_) => {
                println!("ERROR\n");
                process::exit(2);
            }
        };

        let ciphertext: Vec<u8> = encrypt(
            cipher,
            &key2,
            Some(iv),
            infile_contents.as_bytes()
        ).unwrap();
        let buffer = &ciphertext[..];

        //get authentication code
        let mut mac = HmacSha256::new_from_slice(&key2).expect("ERROR");
        mac.update(buffer);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        let mut cipherfile = BufWriter::new(outfile);
        let mut new_tag_file: BufWriter<fs::File> = BufWriter::new(tagfile);
        write_hex(&mut cipherfile,buffer).unwrap();
        write_hex(&mut new_tag_file,&code_bytes).unwrap();
    }
    else if mode == "dec" {
        //TODO
        let cipher = Cipher::aes_256_cbc();
        let f = hex::decode(infile_contents);
        let decoded = match f {
            Ok(decoded) => decoded,
            Err(_) => {
                println!("ERROR\n");
                process::exit(2);
            }
        };
        let buffer = &decoded[..];
        let f = fs::read_to_string(auth_tag);
        let auth_tag_contents = match f {
            Ok(file) => file,
            Err(_) => {
                println!("ERROR\n");
                process::exit(2);
            }
        };
        let decoded_tag = hex::decode(auth_tag_contents).expect("ERROR");
        
        let mut mac = HmacSha256::new_from_slice(&key2).expect("ERROR");
        mac.update(buffer);

        let result = mac.verify_slice(&decoded_tag[..]);

        match result {
            Ok(_n) => {
                let original_text = decrypt(
                    cipher,
                    &key2,
                    Some(iv),
                    buffer).unwrap();
                outfile.write_all(&original_text[..]).expect("ERROR");
            }
            Err(_e) => {
                println!("VERIFICATION FAILURE");
                process::exit(1);
            }
        }
    }
    process::exit(0);
}