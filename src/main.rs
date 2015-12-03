extern crate base64;

use std::error::Error;
use base64::*;

fn main() {
/*
    let result = atob(&"hello yes good this is a testtt ó żółć 한");

    match result {
        Ok(s) => println!("{}", s),
        Err(_) => ()
    }
*/

    //base64::btoa(&"abcd ef g     hi j=k=====l  =m == n=");
    //let a = atob("ABCDEFabcdef01234567").unwrap();
    //println!("{}", a);
    //let b = btoa(&a);

    let c = btoa(&"ABiCDE");

    match c {
        Ok(s) => println!("ok! {}", s),
        Err(e) => println!("err: {}\ndesc: {}", e, e.description())
    }
        

/*
    let tmp = "hello yes good this is a testtt ó żółć 한";

    for (offset, codepoint) in tmp.char_indices() {
        println!("{}: {}", offset, codepoint);
        println!("whitespace? {}", codepoint.is_whitespace());
    }
*/
}
