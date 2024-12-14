#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate winapi;
extern crate kernel32;

#[macro_use]
extern crate log;

mod appcontainer;
mod winffi;

use std::path::Path;

fn event_loop(profile_name: &str, target_path: &Path) -> () {
    info!("profile_name = {:}", profile_name);
    info!("target_path  = {:?}", target_path);

    // XXX: Watch out for the unwrap()
    let profile = match appcontainer::Profile::new(profile_name, target_path.to_str().unwrap()) {
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
    let path = Path::new("C:\\Users\\carra\\AppData\\Local\\Packages\\zweilauncher3\\AC\\game\\LimbusCompany.exe");
    event_loop("zweilauncher3", path);
}
