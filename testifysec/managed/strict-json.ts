// These versioned schemas permit only canonical unsigned safe-integer numbers.
// Validate tokens before JSON.parse can round them; also reject duplicate keys,
// including escaped aliases. This is deliberately a restricted JSON grammar.
export function strictJSON(text: string): unknown {
  let offset = 0
  function whitespace() {
    while (/^[\x20\t\r\n]$/.test(text[offset] ?? "")) offset++
  }
  function string(): string {
    if (text[offset++] !== '"') throw new Error("invalid-json")
    const start = offset - 1
    while (offset < text.length) {
      const char = text[offset++]
      if (char === '"') return JSON.parse(text.slice(start, offset)) as string
      if (char === "\\") offset++
    }
    throw new Error("invalid-json")
  }
  function value(depth: number) {
    if (depth > 32) throw new Error("json-depth")
    whitespace()
    if (text[offset] === '"') return void string()
    if (text[offset] === "{" || text[offset] === "[") {
      const object = text[offset++] === "{"
      const end = object ? "}" : "]"
      const keys = new Set<string>()
      whitespace()
      if (text[offset] === end) return void offset++
      while (offset < text.length) {
        if (object) {
          const key = string()
          if (keys.has(key)) throw new Error("duplicate-json-key")
          keys.add(key)
          whitespace()
          if (text[offset++] !== ":") throw new Error("invalid-json")
        }
        value(depth + 1)
        whitespace()
        if (text[offset] === end) return void offset++
        if (text[offset++] !== ",") throw new Error("invalid-json")
        whitespace()
      }
      throw new Error("invalid-json")
    }
    const literal = /^(?:true|false|null)/.exec(text.slice(offset))
    if (literal) {
      offset += literal[0].length
      return
    }
    const scalar = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(offset))
    if (!scalar) throw new Error("invalid-json")
    // Length and lexical comparison preserve exactness without Number/BigInt
    // conversion, even for an attacker-supplied token thousands of digits long.
    if (!/^(?:0|[1-9][0-9]*)$/.test(scalar[0]) || scalar[0].length > 16 ||
        (scalar[0].length === 16 && scalar[0] > "9007199254740991"))
      throw new Error("invalid-json-number")
    offset += scalar[0].length
  }
  value(0)
  whitespace()
  if (offset !== text.length) throw new Error("invalid-json")
  return JSON.parse(text) as unknown
}
