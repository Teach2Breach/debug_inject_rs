# debug_inject_rs

based on [debug_inject](https://github.com/conix-security/debug_inject)

**Remote Process Injection via debugging**

This is a rust version proof of concept based on the debug_inject project. There are some key differences. The main difference being that the original project did not execute shellcode. It performed some basic file operations, and required significant changes to the logic to execute shellcode. There are many other differences, but I'll let you explore those.

I'll add an 'opsec' branch in the future with additional opsec considerations. It will also be structured to be used as a crate, which can be called from other projects.

## Usage

This project uses litcrypt for string encryption. You must set the 'LITCRYPT_ENCRYPT_KEY' environment variable before running or compiling the project. See the litcrypt documentation for more information: https://crates.io/crates/litcrypt

This PoC is designed to be tested with a target remote process by pid provided on the command line. Testing was performed mostly targeting RuntimeBroker.exe. It may not work with all services, but there are many good options. **This tool requires administrative privileges to achieve debugging elevation. This version must be run as admin.**

Testing:

```
cargo run --release <pid>
```

There are a Lot of print statements in the code. I'm leaving them in for this version for learning purposes. The shellcode is set to pop a calculator. The opsec version will accept shellcode as an argument.

I make no claims to how this will perform against EDR products. Its primary purpose is to be a proof of concept for learning and to have fun resurrecting a cool old project I came across.

I hope you enjoy!





