package server

import (
	"html/template"
	"os"
	"path/filepath"
)

// Templates loads HTML templates from disk.
type Templates struct {
	base *template.Template
}

// NewTemplates parses all templates in the provided directory.
func NewTemplates(dir string) (Templates, error) {
	base := template.New("base").Funcs(template.FuncMap{})

	pattern := filepath.Join(dir, "*.html")
	t, err := base.ParseGlob(pattern)
	if err != nil {
		return Templates{}, err
	}

	return Templates{base: t}, nil
}

// Execute renders the named template to the writer.
func (t Templates) Execute(name string, data any, w interface{ Write([]byte) (int, error) }) error {
	tmpl := t.base.Lookup(name)
	if tmpl == nil {
		return os.ErrNotExist
	}
	return tmpl.Execute(w, data)
}
