extern crate base64;

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
    btoa(&atob("helloooooo").unwrap());

/*
    let tmp = "hello yes good this is a testtt ó żółć 한";

    for (offset, codepoint) in tmp.char_indices() {
        println!("{}: {}", offset, codepoint);
        println!("whitespace? {}", codepoint.is_whitespace());
    }
*/
}
