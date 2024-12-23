#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate kernel32;
extern crate log;
extern crate winapi;

pub mod appcontainer;
pub mod winffi;

pub fn start_game(profile_name: &str, command_line: &str) -> () {
    println!("profile_name = {:}", profile_name);
    println!("command_line = {:?}", command_line);

    let profile = match appcontainer::Profile::new(profile_name, command_line) {
        Ok(val) => {
            println!("New AppContainer profile created!");
            val
        }
        Err(x) => {
            panic!(
                "Failed to create AppContainer profile for {:}: GLE={:}",
                profile_name, x
            );
        }
    };

    println!("profile SID = {:?}", profile.sid);
    match profile.launch() {
        Ok(_) => {
            println!(
                "Child AppContainer'd process launched at {}",
                profile.folder
            );
            return;
        }
        Err(x) => {
            panic!("Failed to launch sandboxed process! GLE={:}", x);
        }
    };
}
