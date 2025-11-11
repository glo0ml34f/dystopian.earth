package markdown

import (
	"bytes"
	"html/template"
	"io/fs"
	"path/filepath"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer/html"
)

// Renderer wraps a goldmark Markdown renderer.
type Renderer struct {
	engine goldmark.Markdown
}

// New returns a configured Renderer.
func New() Renderer {
	md := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,
			extension.DefinitionList,
			extension.Table,
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),
			html.WithXHTML(),
		),
	)

	return Renderer{engine: md}
}

// Render converts markdown bytes to trusted HTML template.
func (r Renderer) Render(data []byte) (template.HTML, error) {
	var buf bytes.Buffer
	if err := r.engine.Convert(data, &buf); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil
}

// DiscoverPages walks the provided filesystem and returns markdown file paths.
func DiscoverPages(fsys fs.FS) ([]string, error) {
	var pages []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(d.Name()) == ".md" {
			pages = append(pages, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pages, nil
}
