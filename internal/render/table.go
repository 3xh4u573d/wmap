package render

import (
	"io"
	"strings"
	"unicode/utf8"
)

type cell struct {
	text  string
	style func(string) string
}

func txt(s string) cell { return cell{text: s} }

type grid struct {
	headers []string
	rows    [][]cell
	indent  string
}

func (g *grid) add(cells ...cell) { g.rows = append(g.rows, cells) }

func (g *grid) empty() bool { return len(g.rows) == 0 }

func (g *grid) write(w io.Writer, s Styles) {
	ncol := len(g.headers)
	for _, r := range g.rows {
		if len(r) > ncol {
			ncol = len(r)
		}
	}
	if ncol == 0 {
		return
	}

	widths := make([]int, ncol)
	for i, h := range g.headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, r := range g.rows {
		for i, c := range r {
			if n := utf8.RuneCountInString(c.text); n > widths[i] {
				widths[i] = n
			}
		}
	}

	writeRow := func(get func(i int) (string, func(string) string)) {
		parts := make([]string, ncol)
		for i := 0; i < ncol; i++ {
			raw, style := get(i)
			padded := raw + strings.Repeat(" ", max(0, widths[i]-utf8.RuneCountInString(raw)))
			if style != nil && strings.TrimSpace(raw) != "" {
				padded = style(padded)
			}
			parts[i] = padded
		}
		io.WriteString(w, strings.TrimRight(g.indent+strings.Join(parts, "  "), " ")+"\n")
	}

	if len(g.headers) > 0 {
		writeRow(func(i int) (string, func(string) string) {
			if i < len(g.headers) {
				return g.headers[i], s.Head
			}
			return "", nil
		})
	}
	for _, r := range g.rows {
		writeRow(func(i int) (string, func(string) string) {
			if i < len(r) {
				return r[i].text, r[i].style
			}
			return "", nil
		})
	}
}
