# VSCode-AggressorScript

A Visual Studio Code extension providing full language support for Cobalt Strike Aggressor Script (`.cna` files), powered by a dedicated Language Server Protocol (LSP) backend.

---

## Features

### Syntax Highlighting

Full TextMate grammar support for AggressorScript, covering:

- Sleep language keywords and control flow (`if`, `else`, `foreach`, `while`, `try`, `catch`, `sub`, `return`)
- Variable sigils (`$`, `@`, `%`)
- String literals, numeric literals, and comments
- Cobalt Strike-specific keywords (`alias`, `on`, `set`, `command`, `popup`)

### IntelliSense Code Completion

Context-aware completions provided by the language server:

| Context     | Completions Provided                                            |
| ----------- | --------------------------------------------------------------- |
| After `&`   | Built-in Cobalt Strike functions                                |
| After `on`  | Event names (e.g., `beacon_initial`, `heartbeat_1m`)            |
| After `set` | Hook constants (e.g., `POWERSHELL_COMMAND`, `ARTIFACT_PAYLOAD`) |
| After `-`   | Predicate helpers (e.g., `-is64`, `-isactive`, `-isbeacon`)     |
| General     | All functions, events, constants, and keywords                  |

### Hover Documentation

Hover over any built-in function, event name, or constant to view its inline documentation, including parameter descriptions and usage notes.

### Document Outline (Symbols)

The Outline panel and breadcrumb navigation are populated with all top-level definitions in the current file:

| Definition type | Symbol kind |
| --------------- | ----------- |
| `sub`           | Function    |
| `alias`         | Function    |
| `command`       | Function    |
| `on`            | Event       |
| `set`           | Constant    |
| `popup`         | Namespace   |

### Snippets

A comprehensive snippet library covers the full Cobalt Strike Aggressor Script API, including Beacon commands, dialog helpers, event handlers, data model accessors, and report elements.

## Extension Settings

This extension does not add any custom configuration entries. It activates automatically when a `.cna` file is opened.

## Getting Started

1. Install the extension from the VS Code Marketplace.
2. Open any `.cna` file or create a new one.
3. The language server starts automatically and all features become available immediately.

## Known Issues

- Semantic analysis (type checking, undefined variable detection) is not yet implemented.
- Go-to-definition for user-defined symbols is planned for a future release.

## Acknowledgements

This extension builds upon the groundwork laid by the following prior projects. Sincere thanks to their authors and contributors.

- [vscode-language-aggressor](https://github.com/darkoperator/vscode-language-aggressor) by [darkoperator (Carlos Perez)](https://github.com/darkoperator) and [am0nsec (Paul L.)](https://github.com/am0nsec) - the original AggressorScript grammar, snippet definitions, and CS function prototypes that formed the foundation of this work.
