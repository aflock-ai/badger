package main

import (
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestStorageToMarkdownGolden(t *testing.T) {
	for _, name := range []string{"basic", "hostile"} {
		in, err := os.ReadFile("testdata/storage/" + name + ".xml")
		if err != nil {
			t.Fatal(err)
		}
		got := storageToMarkdown(string(in)) + "\n"
		golden := "testdata/storage/" + name + ".md"
		if *update {
			os.WriteFile(golden, []byte(got), 0o644)
		}
		want, _ := os.ReadFile(golden)
		if got != string(want) {
			t.Errorf("%s:\n--- got\n%s\n--- want\n%s", name, got, want)
		}
	}
}

// Nesting past maxDepth must collapse into one node, not keep growing the tree.
func TestParseDepthBounded(t *testing.T) {
	in := strings.Repeat(`<ac:structured-macro ac:name="info"><ac:rich-text-body><div>`, 5000) + "deep"
	root, _ := parseStorage(in)
	var depth func(*node) int
	depth = func(n *node) int {
		d := 0
		for _, k := range n.kids {
			d = max(d, depth(k))
		}
		return d + 1
	}
	if d := depth(root); d > maxDepth+3 {
		t.Errorf("tree depth %d", d)
	}
	if !strings.Contains(storageToMarkdown(in), "deep") {
		t.Error("flattened text lost")
	}
}

// ac:link inside ac:link-body, nested to just under the depth cap and repeated: each subtree
// must be rendered once, or this takes 2^23 steps per copy.
func TestNestedLinksLinear(t *testing.T) {
	one := strings.Repeat("<ac:link><ac:link-body>", 23) + "x" + strings.Repeat("</ac:link-body></ac:link>", 23)
	start := time.Now()
	md := storageToMarkdown("<p>" + strings.Repeat(one, 200) + "</p>")
	if d := time.Since(start); d > 2*time.Second || !strings.Contains(md, "x") {
		t.Errorf("took %v", d)
	}
}

func TestFenceLongRun(t *testing.T) {
	start := time.Now()
	f := fence("", "a"+strings.Repeat("`", 200000)+"b")
	if d := time.Since(start); d > time.Second || !strings.HasPrefix(f, strings.Repeat("`", 200001)+"\n") || strings.HasPrefix(f, strings.Repeat("`", 200002)) {
		t.Errorf("fence took %v", d)
	}
}

func TestInlineLinksLinear(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("[", 300000),
		strings.Repeat("[a](", 100000),
		strings.Repeat("[a](https://x", 50000),
		strings.Repeat("[a] ", 100000),
	} {
		start := time.Now()
		markdownToStorage(in)
		if d := time.Since(start); d > time.Second {
			t.Errorf("%.12q...: %v", in, d)
		}
	}
}

func TestMarkdownToStorage(t *testing.T) {
	for in, want := range map[string]string{
		"# Title\ntext *x* `a<b`":        `<h1>Title</h1><p>text *x* <code>a&lt;b</code></p>`,
		"- one\n- **two**\n\n1. a\n2. b": `<ul><li>one</li><li><strong>two</strong></li></ul><ol><li>a</li><li>b</li></ol>`,
		"see [docs](https://x.example.invalid/a?b=1&c=2) and [bad](javascript:x)": `<p>see <a href="https://x.example.invalid/a?b=1&amp;c=2">docs</a> and [bad](javascript:x)</p>`,
		"```go\nfmt.Println(\"]]>\")\n```\n---":                                   `<ac:structured-macro ac:name="code"><ac:parameter ac:name="language">go</ac:parameter><ac:plain-text-body><![CDATA[fmt.Println("]]]]><![CDATA[>")]]></ac:plain-text-body></ac:structured-macro><hr />`,
		"```\"><x>\nraw\n```":                                                     `<ac:structured-macro ac:name="code"><ac:plain-text-body><![CDATA[raw]]></ac:plain-text-body></ac:structured-macro>`,
		"````md\n```go\nx\n```\n````\nafter":                                      "<ac:structured-macro ac:name=\"code\"><ac:parameter ac:name=\"language\">md</ac:parameter><ac:plain-text-body><![CDATA[```go\nx\n```]]></ac:plain-text-body></ac:structured-macro><p>after</p>",
		"[a] [b [c](http://x.example.invalid) [](https://y) [d](https://)":        `<p>[a] [b <a href="http://x.example.invalid">c</a> [](https://y) [d](https://)</p>`,
		"é\u0001ü <ac:link>":                                                      `<p>éü &lt;ac:link&gt;</p>`,
	} {
		if got := markdownToStorage(in); got != want {
			t.Errorf("%q\n got %s\nwant %s", in, got, want)
		}
	}
	// What we write must read back as the same text.
	md := "## Steps\n\n1. Freeze `main`.\n2. Tag **it**."
	if back := storageToMarkdown(markdownToStorage(md)); !strings.Contains(back, md) {
		t.Errorf("round trip: %q", back)
	}
}
