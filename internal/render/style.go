package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type Styles struct{ Color bool }

func (s Styles) paint(str string, mk func(lipgloss.Style) lipgloss.Style) string {
	if !s.Color || strings.TrimSpace(str) == "" {
		return str
	}
	return mk(lipgloss.NewStyle()).Render(str)
}

func fg(c string) func(lipgloss.Style) lipgloss.Style {
	return func(st lipgloss.Style) lipgloss.Style { return st.Foreground(lipgloss.Color(c)) }
}

func fgBold(c string) func(lipgloss.Style) lipgloss.Style {
	return func(st lipgloss.Style) lipgloss.Style { return st.Foreground(lipgloss.Color(c)).Bold(true) }
}

func (s Styles) Title(str string) string { return s.paint(str, fgBold("12")) }
func (s Styles) Head(str string) string {
	return s.paint(str, func(st lipgloss.Style) lipgloss.Style { return st.Bold(true) })
}
func (s Styles) Dim(str string) string {
	return s.paint(str, func(st lipgloss.Style) lipgloss.Style { return st.Faint(true) })
}
func (s Styles) Service(str string) string  { return s.paint(str, fg("6")) }
func (s Styles) Open(str string) string     { return s.paint(str, fg("2")) }
func (s Styles) Closed(str string) string   { return s.paint(str, fg("1")) }
func (s Styles) Filtered(str string) string { return s.paint(str, fg("3")) }
func (s Styles) Added(str string) string    { return s.paint(str, fgBold("2")) }
func (s Styles) Removed(str string) string  { return s.paint(str, fgBold("1")) }
func (s Styles) Changed(str string) string  { return s.paint(str, fgBold("3")) }

func (s Styles) State(state string) string {
	switch {
	case strings.HasPrefix(strings.TrimSpace(state), "open"):
		return s.Open(state)
	case strings.Contains(state, "filtered"):
		return s.Filtered(state)
	default:
		return s.Closed(state)
	}
}
