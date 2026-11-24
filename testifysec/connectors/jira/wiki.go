package main

import (
	"regexp"
	"strings"
)

// Jira wiki markup to markdown, best effort: headings, lists, code and noformat blocks, quotes,
// tables, links, mentions, bold and monospace. Anything else passes through as written.
var (
	wikiHeading = regexp.MustCompile(`^h([1-6])\.\s+(.*)$`)
	wikiList    = regexp.MustCompile(`^([*#-]+)\s+(.*)$`)
	wikiBlock   = regexp.MustCompile(`^\{(code|noformat)(?::([^}|]*))?[^}]*\}(.*)$`)
	wikiMention = regexp.MustCompile(`\[~([^\]]+)\]`)
	wikiLink    = regexp.MustCompile(`\[([^\]|]+)\|([^\]]+)\]`)
	wikiBare    = regexp.MustCompile(`\[((?:https?|mailto):[^\]]+)\]`)
	wikiMono    = regexp.MustCompile(`\{\{(.+?)\}\}`)
	wikiBold    = regexp.MustCompile(`(^|[^\w*])\*([^*\s][^*]*?)\*([^\w*]|$)`)
	wikiColor   = regexp.MustCompile(`\{color(?::[^}]*)?\}`)
)

func wikiToMarkdown(s string) string {
	var out []string
	fence, quote := "", false
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if fence != "" {
			if before, ok := strings.CutSuffix(line, "{"+fence+"}"); ok {
				if before != "" {
					out = append(out, before)
				}
				out, fence = append(out, "```"), ""
			} else {
				out = append(out, line)
			}
			continue
		}
		t := strings.TrimSpace(line)
		if m := wikiBlock.FindStringSubmatch(t); m != nil {
			out, fence = append(out, "```"+strings.TrimSpace(m[2])), m[1]
			if rest, ok := strings.CutSuffix(m[3], "{"+m[1]+"}"); ok {
				out, fence = append(out, rest, "```"), ""
			} else if m[3] != "" {
				out = append(out, m[3])
			}
			continue
		}
		if t == "{quote}" {
			quote = !quote
			continue
		}
		if m := wikiList.FindStringSubmatch(t); m != nil && t != "----" {
			marker := "- "
			if strings.HasSuffix(m[1], "#") {
				marker = "1. "
			}
			t = strings.Repeat("  ", len(m[1])-1) + marker + inline(m[2])
		} else {
			t = inline(t)
			switch m := wikiHeading.FindStringSubmatch(t); {
			case m != nil:
				t = strings.Repeat("#", int(m[1][0]-'0')) + " " + m[2]
			case strings.HasPrefix(t, "bq. "):
				t = "> " + t[4:]
			case t == "----":
				t = "---"
			case strings.HasPrefix(t, "|"):
				t = tableRow(t)
			}
		}
		if quote {
			t = "> " + t
		}
		out = append(out, t)
	}
	if fence != "" {
		out = append(out, "```")
	}
	return strings.Join(out, "\n")
}

func inline(t string) string {
	t = wikiColor.ReplaceAllString(t, "")
	t = wikiMono.ReplaceAllString(t, "`$1`")
	t = wikiMention.ReplaceAllString(t, "@$1")
	t = wikiLink.ReplaceAllString(t, "[$1]($2)")
	t = wikiBare.ReplaceAllString(t, "<$1>")
	return wikiBold.ReplaceAllString(t, "$1**$2**$3")
}

// tableRow turns ||h||h|| and |c|c| rows into markdown, adding the separator under a header.
func tableRow(t string) string {
	header := strings.HasPrefix(t, "||")
	cells := strings.Split(strings.Trim(t, "|"), "|")
	var keep []string
	for _, c := range cells {
		if c = strings.TrimSpace(c); c != "" || !header {
			keep = append(keep, c)
		}
	}
	row := "| " + strings.Join(keep, " | ") + " |"
	if header {
		row += "\n|" + strings.Repeat("---|", len(keep))
	}
	return row
}
