import { describe, expect, it } from "vitest";
import { parseStrictJson, parseStrictJsonBytes } from "../src/json.js";

describe("strict JSON", () => {
  it("parses ordinary documents", () => {
    expect(parseStrictJson('{"a":[1,true,null,"x"]}')).toEqual({
      a: [1, true, null, "x"],
    });
  });

  it("rejects duplicate keys at every depth", () => {
    for (const value of [
      '{"a":1,"a":2}',
      '{"x":{"sub":"one","sub":"two"}}',
      '{"x":[{"seed":1,"seed":2}]}',
    ]) {
      expect(() => parseStrictJson(value)).toThrow("duplicate");
    }
  });

  it("rejects trailing data and malformed values", () => {
    for (const value of ['{"a":1} trailing', '{"a":}', "01", '"unterminated']) {
      expect(() => parseStrictJson(value)).toThrow();
    }
  });

  it("accepts only JSON whitespace", () => {
    expect(parseStrictJson(' \t\r\n{"a":1}\n')).toEqual({ a: 1 });
    for (const value of ['\u00a0{"a":1}', '{"a":1}\u2028', '\u000b{"a":1}']) {
      expect(() => parseStrictJson(value)).toThrow();
    }
  });

  it("rejects invalid UTF-8 byte input", () => {
    expect(() =>
      parseStrictJsonBytes(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d])),
    ).toThrow("invalid UTF-8");
  });
});
