# C Concurrency Firewall Server Project

A concurrent firewall server and client system written in C, supporting multiple clients via threads. The project includes a test script for automated validation.

## Features
- **Concurrent Server:** Handles multiple client connections using POSIX threads.
- **Firewall Rules:** Add, delete, and manage firewall rules for IPs and ports.
- **Client-Server Communication:** Simple protocol for sending commands and receiving responses.
- **Validation:** Input validation for IP addresses and port ranges.
- **Automated Testing:** Includes a shell script for basic and interactive test cases.

## File Structure
- `server.c`: The concurrent firewall server implementation.
- `client.c`: The client program to interact with the server.
- `Makefile`: Build instructions for both server and client.
- `test.sh`: Automated test script for server and client.

## Build Instructions
Requires GCC and POSIX environment (Linux/macOS).

```sh
make
```
This will produce two executables: `server` and `client`.

## Usage
### Start the Server
```sh
./server <port>
```
Or for interactive mode:
```sh
./server -i
```

### Run the Client
```sh
./client <serverHost> <serverPort> <command> [args...]
```
- Example: Add a rule
  ```sh
  ./client localhost 2200 "A 147.188.192.41 443"
  ```

### Supported Commands
- `A <ip> <port>`: Add a firewall rule
- `D <ip> <port>`: Delete a firewall rule
- `L`: List all rules
- `C`: Clear all rules

## Testing
Run the provided test script:
```sh
bash test.sh
```
This will execute both interactive and basic test cases, starting the server and client, and checking expected outputs.
---
