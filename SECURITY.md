# Security Policy

## 🔒 Supported Versions

We actively maintain and provide security updates for the latest stable version of this project.

| Version | Supported |
|----------|------------|
| Latest (main branch) | ✅ Yes |
| Older versions | ❌ No |

Please ensure you are using the latest version before reporting vulnerabilities.

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability, **DO NOT create a public issue.**

Instead:

1. Open a private GitHub Security Advisory:
   - Go to the repository
   - Click "Security"
   - Click "Report a vulnerability"

OR

2. Email the maintainer directly (add your contact email here).

Please include:

- Clear description of the vulnerability
- Steps to reproduce
- Impact assessment
- A minimal reproducible example (if possible)
- Suggested mitigation (optional)

We aim to acknowledge reports within 48 hours.

---

## 🛡 Secure Coding Standards (C++)

This project follows these security principles:

- No raw pointer ownership without clear lifetime management
- Prefer RAII for resource handling
- Avoid undefined behavior
- Avoid buffer overflows
- Avoid unsafe C-style string manipulation
- Validate all external input
- Do not trust user-provided data
- Avoid use-after-free scenarios
- Avoid data races (thread safety must be explicit)

Where possible:

- Prefer `std::string` over `char*`
- Prefer `std::vector` over raw arrays
- Use smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- Enable compiler warnings (`-Wall -Wextra -Werror`)
- Enable sanitizers in development (`-fsanitize=address,undefined`)

---

## 🔐 Memory Safety

Contributors must ensure:

- No memory leaks
- No double free
- No dangling references
- No stack corruption
- No unsafe casts without validation

Pull requests introducing unsafe memory patterns may be rejected.

---

## 🧵 Concurrency Safety

If multithreading is used:

- Avoid data races
- Use `std::mutex` or proper synchronization primitives
- Document thread ownership clearly
- Avoid deadlocks

---

## 📦 Third-Party Dependencies

- Keep dependencies minimal
- Avoid unmaintained libraries
- Review external code before integrating
- Monitor known CVEs

---

## 🔍 Static Analysis

We encourage use of:

- clang-tidy
- cppcheck
- AddressSanitizer
- UBSan
- Valgrind (if applicable)

Security-related pull requests are reviewed with extra scrutiny.

---

## 🏆 Responsible Disclosure

We appreciate responsible disclosure.

Please allow reasonable time for fixes before public discussion.

Researchers will be credited unless anonymity is requested.

---

Thank you for helping make this C++ project secure.
