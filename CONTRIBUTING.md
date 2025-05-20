# Contributing to nf_wgobfs

Thank you for your interest in contributing! We welcome all contributions to improve this project.

## Project Structure

The codebase is organized as follows:

```
src/
├── main.rs             # Filter entry point
├── cli.rs              # CLI argument handling
├── config.rs           # Filter configuration
│
├── filter/
│   ├── obfuscator.rs   # Packet obfuscation
│   ├── keepalive.rs    # Drops keepalive packets
│   └── queue.rs        # NFQUEUE integration
│
├── cipher/
│   ├── chacha6.rs      # ChaCha6 algorithm
│   ├── randomiser.rs   # Secure nonce and ballast generation
│   └── mod.rs
│
└── netutils/
    ├── ipv4.rs         # IPv4 support (checksums, UDP)
    ├── ipv6.rs         # IPv6 support
    └── common.rs       # Common utilities


```

Refer to the `src/` directory for the core logic and to `tests/` for integration tests.

## How to Contribute

1. **Fork the repository** and clone it to your local machine.
2. **Create a new branch** for your feature or bugfix:
    ```sh
    git checkout -b my-feature
    ```
3. **Make your changes** and commit them with clear messages.
4. **Push to your fork** and open a Pull Request (PR) against the `main` branch.

## Development Environment

This project uses a dev container with:
- Debian GNU/Linux 12 (bookworm)
- Rust and common Rust utilities
- Git (latest version)

You can use the provided dev container for a consistent development environment.

## Code Style

- Follow [Rust formatting guidelines](https://doc.rust-lang.org/1.0.0/style/).
- Run `cargo fmt` before submitting your PR.
- Ensure all tests pass with `cargo test`.

## Reporting Issues

If you find a bug or have a feature request, please [open an issue](https://github.com/your-repo/nf_wgobfs/issues) with details and steps to reproduce.

## Pull Request Checklist

- [ ] Code compiles and passes tests
- [ ] Linting and formatting applied
- [ ] PR description explains the change

## Questions?

Feel free to open an issue or start a discussion.

Thank you for contributing!