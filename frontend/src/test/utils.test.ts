import { describe, expect, it } from "vitest";
import { csvEscape, parseUrlList, toCsv } from "../utils/csv";
import { validateUrlInput } from "../utils/validateUrl";

describe("validateUrlInput", () => {
  it.each([["", /Enter a URL/], ["   ", /Enter a URL/], ["http://a b.com", /spaces/], ["ftp://x.com", /http/], ["http://", /hostname/], ["a".repeat(2100), /2048/]])("rejects %j", (v, re) => {
    expect(validateUrlInput(v)).toMatch(re);
  });
  it.each(["https://example.com", "example.com/path", "http://192.168.0.1:8080/x", "//example.com"])("accepts %j", (v) => {
    expect(validateUrlInput(v)).toBeNull();
  });
});

describe("csv helpers", () => {
  it("parses plain lists, headers and quoted cells", () => {
    expect(parseUrlList("url\nhttps://a.com\n\nhttps://b.com/x?y=1,2")).toEqual(["https://a.com", "https://b.com/x?y=1"]);
    expect(parseUrlList('id,url\n1,"https://c.com/a,b"')).toEqual(["https://c.com/a,b"]);
    expect(parseUrlList("")).toEqual([]);
  });
  it("neutralises spreadsheet formulas and quotes special characters", () => {
    expect(csvEscape("=HYPERLINK(1)")).toBe("'=HYPERLINK(1)");
    expect(csvEscape('a,"b"')).toBe('"a,""b"""');
    expect(toCsv([["a", 1], [null, "x"]])).toBe("a,1\n,x");
  });
});
