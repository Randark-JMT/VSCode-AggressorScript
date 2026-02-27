import {
  createConnection,
  TextDocuments,
  ProposedFeatures,
  InitializeParams,
  InitializeResult,
  TextDocumentSyncKind,
  CompletionItem,
  CompletionItemKind,
  TextDocumentPositionParams,
  HoverParams,
  Hover,
  DocumentSymbolParams,
  DocumentSymbol,
  SymbolKind,
  Range,
  Position,
  InsertTextFormat,
} from "vscode-languageserver/node";
import { TextDocument } from "vscode-languageserver-textdocument";
import { ALL_COMPLETIONS, HOVER_MAP } from "./data";

// Create a connection for the server using Node's IPC
const connection = createConnection(ProposedFeatures.all);

// Manage open text documents
const documents = new TextDocuments(TextDocument);

connection.onInitialize((_params: InitializeParams): InitializeResult => {
  return {
    capabilities: {
      textDocumentSync: TextDocumentSyncKind.Incremental,
      completionProvider: {
        resolveProvider: false,
        triggerCharacters: ["$", "@", "%", "&", " "],
      },
      hoverProvider: true,
      documentSymbolProvider: true,
    },
    serverInfo: {
      name: "aggressorscript-lsp",
      version: "0.1.0",
    },
  };
});

// ---------------------------------------------------------------------------
// Completion
// ---------------------------------------------------------------------------
connection.onCompletion(
  (params: TextDocumentPositionParams): CompletionItem[] => {
    const doc = documents.get(params.textDocument.uri);
    if (!doc) return [];

    const text = doc.getText();
    const offset = doc.offsetAt(params.position);
    const lineStart = text.lastIndexOf("\n", offset - 1) + 1;
    const lineText = text.slice(lineStart, offset);

    // Determine context for smarter filtering
    const isAfterAmpersand = lineText.endsWith("&");
    const isVariable = /[\$@%]$/.test(lineText);
    const isAfterOn = /\bon\s+\w*$/.test(lineText);
    const isAfterSet = /\bset\s+\w*$/.test(lineText);

    if (isAfterAmpersand) {
      // Only functions
      return ALL_COMPLETIONS.filter(
        (c) => c.kind === CompletionItemKind.Function
      );
    }

    if (isVariable) {
      // No completions for variable sigils (let the user type the name)
      return [];
    }

    if (isAfterOn) {
      // Only events
      return ALL_COMPLETIONS.filter(
        (c) => c.kind === CompletionItemKind.Event
      );
    }

    if (isAfterSet) {
      // Only hooks
      return ALL_COMPLETIONS.filter(
        (c) => c.kind === CompletionItemKind.Constant
      );
    }

    return ALL_COMPLETIONS;
  }
);

// ---------------------------------------------------------------------------
// Hover
// ---------------------------------------------------------------------------
connection.onHover((params: HoverParams): Hover | null => {
  const doc = documents.get(params.textDocument.uri);
  if (!doc) return null;

  const word = getWordAtPosition(doc, params.position);
  if (!word) return null;

  const hoverContent = HOVER_MAP.get(word);
  if (!hoverContent) return null;

  return { contents: hoverContent };
});

// ---------------------------------------------------------------------------
// Document symbols (Outline)
// ---------------------------------------------------------------------------
connection.onDocumentSymbol(
  (params: DocumentSymbolParams): DocumentSymbol[] => {
    const doc = documents.get(params.textDocument.uri);
    if (!doc) return [];

    return extractSymbols(doc);
  }
);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function getWordAtPosition(doc: TextDocument, position: Position): string | null {
  const text = doc.getText();
  const offset = doc.offsetAt(position);

  // Walk backward to find start of word
  let start = offset;
  while (start > 0 && isWordChar(text[start - 1])) {
    start--;
  }
  // Strip leading & sigil if present
  if (start > 0 && text[start - 1] === "&") {
    start--;
  }

  // Walk forward to find end of word
  let end = offset;
  while (end < text.length && isWordChar(text[end])) {
    end++;
  }

  if (start === end) return null;

  const raw = text.slice(start, end);
  // Remove leading & if present
  return raw.startsWith("&") ? raw.slice(1) : raw;
}

function isWordChar(ch: string): boolean {
  return /[a-zA-Z0-9_]/.test(ch);
}

// Pattern to match function/alias/sub/on/command definitions
const SYMBOL_PATTERNS: Array<{
  regex: RegExp;
  kind: SymbolKind;
  nameGroup: number;
}> = [
  {
    regex: /^\s*(sub)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{/gm,
    kind: SymbolKind.Function,
    nameGroup: 2,
  },
  {
    regex: /^\s*(alias)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{/gm,
    kind: SymbolKind.Function,
    nameGroup: 2,
  },
  {
    regex: /^\s*(command)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{/gm,
    kind: SymbolKind.Function,
    nameGroup: 2,
  },
  {
    regex: /^\s*(on)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{/gm,
    kind: SymbolKind.Event,
    nameGroup: 2,
  },
  {
    regex: /^\s*(set)\s+([A-Z_][A-Z0-9_]*)\s*\{/gm,
    kind: SymbolKind.Constant,
    nameGroup: 2,
  },
  {
    regex: /^\s*(popup)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{/gm,
    kind: SymbolKind.Namespace,
    nameGroup: 2,
  },
];

function extractSymbols(doc: TextDocument): DocumentSymbol[] {
  const text = doc.getText();
  const symbols: DocumentSymbol[] = [];

  for (const { regex, kind, nameGroup } of SYMBOL_PATTERNS) {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const name = match[nameGroup];
      const matchStart = match.index;
      const matchEnd = matchStart + match[0].length;

      const startPos = doc.positionAt(matchStart);
      const endPos = doc.positionAt(matchEnd);

      // Find matching closing brace for the full range
      const closeEnd = findClosingBrace(text, matchEnd - 1);
      const closePos = closeEnd >= 0 ? doc.positionAt(closeEnd + 1) : endPos;

      const range: Range = {
        start: startPos,
        end: closePos,
      };
      const selectionRange: Range = {
        start: startPos,
        end: endPos,
      };

      symbols.push({
        name,
        kind,
        range,
        selectionRange,
      });
    }
  }

  return symbols;
}

function findClosingBrace(text: string, openPos: number): number {
  let depth = 0;
  for (let i = openPos; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}") {
      depth--;
      if (depth === 0) return i;
    } else if (text[i] === "#") {
      // Skip comments
      while (i < text.length && text[i] !== "\n") i++;
    } else if (text[i] === '"') {
      // Skip double-quoted strings
      i++;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === "\\") i++;
        i++;
      }
    } else if (text[i] === "'") {
      // Skip single-quoted strings
      i++;
      while (i < text.length && text[i] !== "'") {
        if (text[i] === "\\") i++;
        i++;
      }
    }
  }
  return -1;
}

// Make the text document manager listen on the connection
documents.listen(connection);
connection.listen();
