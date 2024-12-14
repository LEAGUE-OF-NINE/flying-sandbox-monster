#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate winapi;
extern crate kernel32;

#[macro_use]
extern crate log;

mod appcontainer;
mod winffi;

use std::path::Path;

fn start_game(profile_name: &str, command_line: &str) -> () {
    info!("profile_name = {:}", profile_name);
    info!("command_line = {:?}", command_line);

    let profile = match appcontainer::Profile::new(profile_name, command_line) {
        Ok(val) => {
            info!("New AppContainer profile created!");
            val
        }
        Err(x) => {
            error!("Failed to create AppContainer profile for {:}: GLE={:}",
                   profile_name,
                   x);
            return;
        }
    };

    info!("profile SID = {:?}", profile.sid);
    match profile.launch() {
        Ok(val) => {
            info!("Child AppContainer'd process launched!");
            val
        }
        Err(x) => {
            error!("Failed to launch sandboxed process! GLE={:}", x);
            return;
        }
    };
}

fn main() {
    let cmd_line = "C:\\Users\\carra\\AppData\\Local\\Packages\\zweilauncher3\\AC\\game\\LimbusCompany.exe";
    start_game("zweilauncher3", cmd_line);
}
