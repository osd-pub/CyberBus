/**
 * Strict JSON for JWT and OIDC documents. Duplicate object keys are rejected
 * recursively, matching cyberbus-auth's strict.rs behavior.
 */
export function parseStrictJson(text: string): unknown {
  const parser = new Parser(text);
  const value = parser.value(0);
  parser.ws();
  if (!parser.done()) {
    throw new Error("trailing JSON data");
  }
  return value;
}

export function parseStrictJsonBytes(bytes: Uint8Array): unknown {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("invalid UTF-8 JSON");
  }
  return parseStrictJson(text);
}

export function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

export function array(value: unknown): unknown[] | undefined {
  return Array.isArray(value) ? value : undefined;
}

export function string(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function integer(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value)
    ? value
    : undefined;
}

class Parser {
  private index = 0;

  constructor(private readonly source: string) {}

  done(): boolean {
    return this.index === this.source.length;
  }

  ws(): void {
    while (
      this.index < this.source.length &&
      /[ \t\n\r]/u.test(this.source[this.index] ?? "")
    ) {
      this.index += 1;
    }
  }

  value(depth: number): unknown {
    if (depth > 64) {
      throw new Error("JSON nesting limit");
    }
    this.ws();
    const character = this.source[this.index];
    if (character === "{") {
      return this.object(depth + 1);
    }
    if (character === "[") {
      return this.array(depth + 1);
    }
    if (character === '"') {
      return this.string();
    }
    if (character === "t" && this.take("true")) {
      return true;
    }
    if (character === "f" && this.take("false")) {
      return false;
    }
    if (character === "n" && this.take("null")) {
      return null;
    }
    return this.number();
  }

  private object(depth: number): Record<string, unknown> {
    this.index += 1;
    const out: Record<string, unknown> = Object.create(null);
    this.ws();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.source[this.index] !== '"') {
        throw new Error("invalid JSON object key");
      }
      const key = this.string();
      if (Object.hasOwn(out, key)) {
        throw new Error("duplicate JSON key");
      }
      this.ws();
      if (this.source[this.index] !== ":") {
        throw new Error("invalid JSON object");
      }
      this.index += 1;
      out[key] = this.value(depth);
      this.ws();
      const separator = this.source[this.index];
      if (separator === "}") {
        this.index += 1;
        return out;
      }
      if (separator !== ",") {
        throw new Error("invalid JSON object separator");
      }
      this.index += 1;
    }
  }

  private array(depth: number): unknown[] {
    this.index += 1;
    const out: unknown[] = [];
    this.ws();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return out;
    }
    for (;;) {
      out.push(this.value(depth));
      this.ws();
      const separator = this.source[this.index];
      if (separator === "]") {
        this.index += 1;
        return out;
      }
      if (separator !== ",") {
        throw new Error("invalid JSON array separator");
      }
      this.index += 1;
    }
  }

  private string(): string {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.source.length) {
      const character = this.source[this.index];
      if (escaped) {
        escaped = false;
        this.index += 1;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        this.index += 1;
        continue;
      }
      if (character === '"') {
        this.index += 1;
        const raw = this.source.slice(start, this.index);
        try {
          return JSON.parse(raw) as string;
        } catch {
          throw new Error("invalid JSON string");
        }
      }
      if (character !== undefined && character.charCodeAt(0) < 0x20) {
        throw new Error("invalid JSON control character");
      }
      this.index += 1;
    }
    throw new Error("unterminated JSON string");
  }

  private number(): number {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
      this.source.slice(this.index),
    );
    if (match === null) {
      throw new Error("invalid JSON value");
    }
    this.index += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value)) {
      throw new Error("invalid JSON number");
    }
    return value;
  }

  private take(literal: string): boolean {
    if (!this.source.startsWith(literal, this.index)) {
      return false;
    }
    this.index += literal.length;
    return true;
  }
}
