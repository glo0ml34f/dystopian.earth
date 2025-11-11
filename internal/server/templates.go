package server

import (
	"html/template"
	"io"
	"os"
	"path/filepath"
)

// Templates loads HTML templates from disk.
type Templates struct {
	views map[string]*template.Template
}

// NewTemplates parses all templates in the provided directory.
func NewTemplates(dir string) (Templates, error) {
	funcs := template.FuncMap{}

	layoutPath := filepath.Join(dir, "layout.html")
	base, err := template.New("layout").Funcs(funcs).ParseFiles(layoutPath)
	if err != nil {
		return Templates{}, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return Templates{}, err
	}

	views := make(map[string]*template.Template)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".html" {
			continue
		}
		if entry.Name() == "layout.html" {
			continue
		}

		clone, err := base.Clone()
		if err != nil {
			return Templates{}, err
		}

		_, err = clone.ParseFiles(filepath.Join(dir, entry.Name()))
		if err != nil {
			return Templates{}, err
		}

		views[entry.Name()] = clone
	}

	return Templates{views: views}, nil
}

// Execute renders the named template to the writer.
func (t Templates) Execute(name string, data any, w io.Writer) error {
	tmpl, ok := t.views[name]
	if !ok {
		return os.ErrNotExist
	}
	return tmpl.ExecuteTemplate(w, name, data)
}
