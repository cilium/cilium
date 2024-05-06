package gitignore

import (
	"bytes"
	"io/ioutil"
	"os"
	"os/user"
	"strings"

	"gopkg.in/src-d/go-billy.v4"
	"gopkg.in/src-d/go-git.v4/plumbing/format/config"
	gioutil "gopkg.in/src-d/go-git.v4/utils/ioutil"
)

const (
	commentPrefix = "#"
	coreSection   = "core"
	eol           = "\n"
	excludesfile  = "excludesfile"
	gitDir        = ".git"
	gitignoreFile = ".gitignore"
	gitconfigFile = ".gitconfig"
	systemFile    = "/etc/gitconfig"
)

// readIgnoreFile reads a specific git ignore file.
func readIgnoreFile(fs billy.Filesystem, path []string, ignoreFile string) (ps []Pattern, err error) {
	f, err := fs.Open(fs.Join(append(path, ignoreFile)...))
	if err == nil {
		defer f.Close()

		if data, err := ioutil.ReadAll(f); err == nil {
			for _, s := range strings.Split(string(data), eol) {
				if !strings.HasPrefix(s, commentPrefix) && len(strings.TrimSpace(s)) > 0 {
					ps = append(ps, ParsePattern(s, path))
				}
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	return
}

// ReadPatterns reads gitignore patterns recursively traversing through the directory
// structure. The result is in the ascending order of priority (last higher).
func ReadPatterns(fs billy.Filesystem, path []string) (ps []Pattern, err error) {
	ps, _ = readIgnoreFile(fs, path, gitignoreFile)

	var fis []os.FileInfo
	fis, err = fs.ReadDir(fs.Join(path...))
	if err != nil {
		return
	}

	for _, fi := range fis {
		if fi.IsDir() && fi.Name() != gitDir {
			var subps []Pattern
			subps, err = ReadPatterns(fs, append(path, fi.Name()))
			if err != nil {
				return
			}

			if len(subps) > 0 {
				ps = append(ps, subps...)
			}
		}
	}

	return
}

func loadPatterns(fs billy.Filesystem, path string) (ps []Pattern, err error) {
	f, err := fs.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	defer gioutil.CheckClose(f, &err)

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return
	}

	d := config.NewDecoder(bytes.NewBuffer(b))

	raw := config.New()
	if err = d.Decode(raw); err != nil {
		return
	}

	s := raw.Section(coreSection)
	efo := s.Options.Get(excludesfile)
	if efo == "" {
		return nil, nil
	}

	ps, err = readIgnoreFile(fs, nil, efo)
	if os.IsNotExist(err) {
		return nil, nil
	}

	return
}

// LoadGlobalPatterns loads gitignore patterns from from the gitignore file
// declared in a user's ~/.gitconfig file.  If the ~/.gitconfig file does not
// exist the function will return nil.  If the core.excludesfile property
// is not declared, the function will return nil.  If the file pointed to by
// the core.excludesfile property does not exist, the function will return nil.
//
// The function assumes fs is rooted at the root filesystem.
func LoadGlobalPatterns(fs billy.Filesystem) (ps []Pattern, err error) {
	usr, err := user.Current()
	if err != nil {
		return
	}

	return loadPatterns(fs, fs.Join(usr.HomeDir, gitconfigFile))
}

// LoadSystemPatterns loads gitignore patterns from from the gitignore file
// declared in a system's /etc/gitconfig file.  If the ~/.gitconfig file does
// not exist the function will return nil.  If the core.excludesfile property
// is not declared, the function will return nil.  If the file pointed to by
// the core.excludesfile property does not exist, the function will return nil.
//
// The function assumes fs is rooted at the root filesystem.
func LoadSystemPatterns(fs billy.Filesystem) (ps []Pattern, err error) {
	return loadPatterns(fs, systemFile)
}
