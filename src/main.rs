extern crate base64;

fn main() {
    let result = base64::atob(&"hello yes good this is a testtt ó żółć 한");

    match result {
        Ok(s) => println!("{}", s),
        Err(_) => ()
    }
}
