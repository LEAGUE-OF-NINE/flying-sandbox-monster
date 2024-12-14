#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg(windows)]

extern crate winapi;
extern crate kernel32;
extern crate field_offset;
extern crate libc;
extern crate widestring;
extern crate log;

#[allow(unused_imports)]
use log::*;
use super::winffi;

use super::winffi::{HRESULT_FROM_WIN32, SE_GROUP_ENABLED, string_to_sid, sid_to_string,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, LPSTARTUPINFOEXW,
                    HandlePtr, HANDLE_FLAG_INHERIT};
use self::winapi::{DWORD, LPVOID, LPWSTR, PSID, INVALID_HANDLE_VALUE, PSID_AND_ATTRIBUTES,
                   SID_AND_ATTRIBUTES, ERROR_SUCCESS, ERROR_ALREADY_EXISTS, HRESULT,
                   SECURITY_CAPABILITIES, LPPROC_THREAD_ATTRIBUTE_LIST,
                   PPROC_THREAD_ATTRIBUTE_LIST, SIZE_T, PSIZE_T, PVOID, PSECURITY_CAPABILITIES,
                   STARTUPINFOW, LPSTARTUPINFOW, HANDLE, WORD, LPBYTE, STARTF_USESTDHANDLES,
                   STARTF_USESHOWWINDOW, SW_HIDE, ERROR_FILE_NOT_FOUND, PROCESS_INFORMATION,
                   EXTENDED_STARTUPINFO_PRESENT, LPSECURITY_ATTRIBUTES};
use std::path::Path;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::iter::once;
use std::mem;

#[cfg(test)]
use std::env;

#[cfg(test)]
use std::path::PathBuf;
use winapi::LPCWSTR;
#[cfg(test)]
use self::winapi::{INFINITE, WAIT_OBJECT_0};

#[allow(dead_code)]
pub struct Profile {
    pub profile: String,
    command_line: String,
    outbound_network: bool,
    debug: bool,
    pub sid: String,
}

#[allow(dead_code)]
impl Profile {
    pub fn new(profile: &str, path: &str) -> Result<Profile, HRESULT> {
        let mut pSid: PSID = 0 as PSID;
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();

        let path_obj = Path::new(path);
        if !path_obj.exists() || !path_obj.is_file() {
            return Err(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND));
        }

        let mut hr = unsafe {
            winffi::CreateAppContainerProfile(profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              profile_name.as_ptr(),
                                              0 as PSID_AND_ATTRIBUTES,
                                              0 as DWORD,
                                              &mut pSid)
        };

        if hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) {
            hr = unsafe {
                winffi::DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
            };
            if hr != (ERROR_SUCCESS as HRESULT) {
                return Err(hr);
            }
        }

        let string_sid = match sid_to_string(pSid) {
            Ok(x) => x,
            Err(x) => return Err(x as HRESULT),
        };

        unsafe { winffi::FreeSid(pSid) };

        Ok(Profile {
            profile: profile.to_string(),
            command_line: path.to_string(),
            outbound_network: true,
            debug: false,
            sid: string_sid,
        })
    }

    pub fn remove(profile: &str) -> bool {
        let profile_name: Vec<u16> = OsStr::new(profile)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pSid: PSID = 0 as PSID;

        let mut hr = unsafe {
            winffi::DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut pSid)
        };

        if hr == (ERROR_SUCCESS as HRESULT) {
            hr = unsafe { winffi::DeleteAppContainerProfile(profile_name.as_ptr()) };
            return hr == (ERROR_SUCCESS as HRESULT);
        }

        false
    }

    pub fn enable_outbound_network(&mut self, has_outbound_network: bool) {
        self.outbound_network = has_outbound_network;
    }

    pub fn enable_debug(&mut self, is_debug: bool) {
        self.debug = is_debug;
    }

    pub fn launch(&self) -> Result<HandlePtr, DWORD> {
        let network_allow_sid = match string_to_sid("S-1-15-3-1") {
            Ok(x) => x,
            Err(_) => return Err(0xffffffff),
        };
        let sid = string_to_sid(&self.sid)?;
        let mut capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: sid.raw_ptr,
            Capabilities: 0 as PSID_AND_ATTRIBUTES,
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut attrs;
        let mut si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: 0 as DWORD,
                lpReserved: 0 as LPWSTR,
                lpDesktop: 0 as LPWSTR,
                lpTitle: 0 as LPWSTR,
                dwX: 0 as DWORD,
                dwY: 0 as DWORD,
                dwXSize: 0 as DWORD,
                dwYSize: 0 as DWORD,
                dwXCountChars: 0 as DWORD,
                dwYCountChars: 0 as DWORD,
                dwFillAttribute: 0 as DWORD,
                dwFlags: 0 as DWORD,
                wShowWindow: 0 as WORD,
                cbReserved2: 0 as WORD,
                lpReserved2: 0 as LPBYTE,
                hStdInput: 0 as HANDLE,
                hStdOutput: 0 as HANDLE,
                hStdError: 0 as HANDLE,
            },
            lpAttributeList: 0 as PPROC_THREAD_ATTRIBUTE_LIST,
        };
        let mut dwCreationFlags: DWORD = 0 as DWORD;
        let mut attrBuf: Vec<u8>;

        if !self.debug {
            debug!("Setting up AppContainer");

            if self.outbound_network {
                debug!("Setting up SID_AND_ATTRIBUTES for outbound network permissions");

                attrs = SID_AND_ATTRIBUTES {
                    Sid: network_allow_sid.raw_ptr,
                    Attributes: SE_GROUP_ENABLED,
                };

                capabilities.CapabilityCount = 1;
                capabilities.Capabilities = &mut attrs;
            }

            let mut listSize: SIZE_T = 0;
            if unsafe {
                kernel32::InitializeProcThreadAttributeList(0 as LPPROC_THREAD_ATTRIBUTE_LIST,
                                                            1,
                                                            0,
                                                            &mut listSize)
            } !=
                0 {
                debug!("InitializeProcThreadAttributeList failed: GLE={:}",
                       unsafe { kernel32::GetLastError() });
                return Err(unsafe { kernel32::GetLastError() });
            }

            attrBuf = Vec::with_capacity(listSize as usize);
            if unsafe {
                kernel32::InitializeProcThreadAttributeList(attrBuf.as_mut_ptr() as
                                                                LPPROC_THREAD_ATTRIBUTE_LIST,
                                                            1,
                                                            0,
                                                            &mut listSize)
            } ==
                0 {
                debug!("InitializeProcThreadAttributeList failed: GLE={:}",
                       unsafe { kernel32::GetLastError() });
                return Err(unsafe { kernel32::GetLastError() });
            }

            if unsafe {
                kernel32::UpdateProcThreadAttribute(attrBuf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST,
                                                    0,
                                                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                                    mem::transmute::<PSECURITY_CAPABILITIES, LPVOID>(&mut capabilities),
                                                    mem::size_of::<SECURITY_CAPABILITIES>() as SIZE_T,
                                                    0 as PVOID,
                                                    0 as PSIZE_T)
            } == 0 {
                debug!("UpdateProcThreadAttribute failed: GLE={:}", unsafe { kernel32::GetLastError() });
                return Err(unsafe { kernel32::GetLastError() });
            }

            si.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as DWORD;
            si.lpAttributeList = attrBuf.as_mut_ptr() as PPROC_THREAD_ATTRIBUTE_LIST;

            dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
        } else {
            debug!("Debug mode -- no extended STARTUPINFO");
            si.StartupInfo.cb = mem::size_of::<STARTUPINFOW>() as DWORD;
        }

        si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;

        si.StartupInfo.wShowWindow = SW_HIDE as WORD;

        let cmdLine: Vec<u16> = OsStr::new(&self.command_line)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut pi = PROCESS_INFORMATION {
            hProcess: 0 as HANDLE,
            hThread: 0 as HANDLE,
            dwProcessId: 0 as DWORD,
            dwThreadId: 0 as DWORD,
        };

        if unsafe {
            kernel32::CreateProcessW(0 as LPCWSTR,
                                     cmdLine.as_ptr() as LPWSTR,
                                     0 as LPSECURITY_ATTRIBUTES,
                                     0 as LPSECURITY_ATTRIBUTES,
                                     1,
                                     dwCreationFlags,
                                     0 as LPVOID,
                                     0 as LPWSTR,
                                     mem::transmute::<LPSTARTUPINFOEXW, LPSTARTUPINFOW>(&mut si),
                                     &mut pi)
        } == 0 {
            println!("CreateProcess failed: GLE={:}",
                     unsafe { kernel32::GetLastError() });
            return Err(unsafe { kernel32::GetLastError() });
        }

        debug!("  Child PID = {:}", pi.dwProcessId);

        unsafe { kernel32::CloseHandle(pi.hThread) };

        Ok(HandlePtr::new(pi.hProcess))
    }
}

// ----- UNIT TESTS -----
#[test]
fn test_profile_sid() {
    {
        let result = Profile::new("default_profile", "INVALID_FILE");
        assert!(result.is_err());
    }

    {
        let mut result = Profile::new("cmd_profile", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let profile = result.unwrap();

        result = Profile::new("cmd_profile", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let same_profile = result.unwrap();
        assert_eq!(profile.sid, same_profile.sid);

        assert!(Profile::remove("cmd_profile"));

        result = Profile::new("cmd_profile1", "\\Windows\\System32\\cmd.exe");
        assert!(result.is_ok());

        let new_profile = result.unwrap();
        assert!(profile.sid != new_profile.sid);
    }
}

#[cfg(test)]
fn get_unittest_support_path() -> Option<PathBuf> {
    let mut dir_path = match env::current_exe() {
        Ok(x) => x,
        Err(_) => return None,
    };

    while dir_path.pop() {
        dir_path.push("unittest_support");
        if dir_path.exists() && dir_path.is_dir() {
            return Some(dir_path);
        }
        dir_path.pop();
    }

    None
}

#[cfg(test)]
struct ProfileWrapper {
    name: String,
}

#[cfg(test)]
impl Drop for ProfileWrapper {
    fn drop(&mut self) {
        Profile::remove(&self.name);
    }
}

#[cfg(test)]
const OUTBOUND_CONNECT_MASK: u32 = 0x00000001;
#[cfg(test)]
const FILE_READ_MASK: u32 = 0x00000002;
#[cfg(test)]
const FILE_WRITE_MASK: u32 = 0x00000004;
#[cfg(test)]
const REGISTRY_READ_MASK: u32 = 0x00000008;
#[cfg(test)]
const REGISTRY_WRITE_MASK: u32 = 0x00000010;