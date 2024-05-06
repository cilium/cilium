// Package config contains the abstraction of multiple config files
package config

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"gopkg.in/src-d/go-git.v4/internal/url"
	format "gopkg.in/src-d/go-git.v4/plumbing/format/config"
)

const (
	// DefaultFetchRefSpec is the default refspec used for fetch.
	DefaultFetchRefSpec = "+refs/heads/*:refs/remotes/%s/*"
	// DefaultPushRefSpec is the default refspec used for push.
	DefaultPushRefSpec = "refs/heads/*:refs/heads/*"
)

// ConfigStorer generic storage of Config object
type ConfigStorer interface {
	Config() (*Config, error)
	SetConfig(*Config) error
}

var (
	ErrInvalid               = errors.New("config invalid key in remote or branch")
	ErrRemoteConfigNotFound  = errors.New("remote config not found")
	ErrRemoteConfigEmptyURL  = errors.New("remote config: empty URL")
	ErrRemoteConfigEmptyName = errors.New("remote config: empty name")
)

// Config contains the repository configuration
// ftp://www.kernel.org/pub/software/scm/git/docs/git-config.html#FILES
type Config struct {
	Core struct {
		// IsBare if true this repository is assumed to be bare and has no
		// working directory associated with it.
		IsBare bool
		// Worktree is the path to the root of the working tree.
		Worktree string
		// CommentChar is the character indicating the start of a
		// comment for commands like commit and tag
		CommentChar string
	}

	Pack struct {
		// Window controls the size of the sliding window for delta
		// compression.  The default is 10.  A value of 0 turns off
		// delta compression entirely.
		Window uint
	}

	// Remotes list of repository remotes, the key of the map is the name
	// of the remote, should equal to RemoteConfig.Name.
	Remotes map[string]*RemoteConfig
	// Submodules list of repository submodules, the key of the map is the name
	// of the submodule, should equal to Submodule.Name.
	Submodules map[string]*Submodule
	// Branches list of branches, the key is the branch name and should
	// equal Branch.Name
	Branches map[string]*Branch
	// Raw contains the raw information of a config file. The main goal is
	// preserve the parsed information from the original format, to avoid
	// dropping unsupported fields.
	Raw *format.Config
}

// NewConfig returns a new empty Config.
func NewConfig() *Config {
	config := &Config{
		Remotes:    make(map[string]*RemoteConfig),
		Submodules: make(map[string]*Submodule),
		Branches:   make(map[string]*Branch),
		Raw:        format.New(),
	}

	config.Pack.Window = DefaultPackWindow

	return config
}

// Validate validates the fields and sets the default values.
func (c *Config) Validate() error {
	for name, r := range c.Remotes {
		if r.Name != name {
			return ErrInvalid
		}

		if err := r.Validate(); err != nil {
			return err
		}
	}

	for name, b := range c.Branches {
		if b.Name != name {
			return ErrInvalid
		}

		if err := b.Validate(); err != nil {
			return err
		}
	}

	return nil
}

const (
	remoteSection    = "remote"
	submoduleSection = "submodule"
	branchSection    = "branch"
	coreSection      = "core"
	packSection      = "pack"
	fetchKey         = "fetch"
	urlKey           = "url"
	bareKey          = "bare"
	worktreeKey      = "worktree"
	commentCharKey   = "commentChar"
	windowKey        = "window"
	mergeKey         = "merge"
	rebaseKey        = "rebase"

	// DefaultPackWindow holds the number of previous objects used to
	// generate deltas. The value 10 is the same used by git command.
	DefaultPackWindow = uint(10)
)

// Unmarshal parses a git-config file and stores it.
func (c *Config) Unmarshal(b []byte) error {
	r := bytes.NewBuffer(b)
	d := format.NewDecoder(r)

	c.Raw = format.New()
	if err := d.Decode(c.Raw); err != nil {
		return err
	}

	c.unmarshalCore()
	if err := c.unmarshalPack(); err != nil {
		return err
	}
	unmarshalSubmodules(c.Raw, c.Submodules)

	if err := c.unmarshalBranches(); err != nil {
		return err
	}

	return c.unmarshalRemotes()
}

func (c *Config) unmarshalCore() {
	s := c.Raw.Section(coreSection)
	if s.Options.Get(bareKey) == "true" {
		c.Core.IsBare = true
	}

	c.Core.Worktree = s.Options.Get(worktreeKey)
	c.Core.CommentChar = s.Options.Get(commentCharKey)
}

func (c *Config) unmarshalPack() error {
	s := c.Raw.Section(packSection)
	window := s.Options.Get(windowKey)
	if window == "" {
		c.Pack.Window = DefaultPackWindow
	} else {
		winUint, err := strconv.ParseUint(window, 10, 32)
		if err != nil {
			return err
		}
		c.Pack.Window = uint(winUint)
	}
	return nil
}

func (c *Config) unmarshalRemotes() error {
	s := c.Raw.Section(remoteSection)
	for _, sub := range s.Subsections {
		r := &RemoteConfig{}
		if err := r.unmarshal(sub); err != nil {
			return err
		}

		c.Remotes[r.Name] = r
	}

	return nil
}

func unmarshalSubmodules(fc *format.Config, submodules map[string]*Submodule) {
	s := fc.Section(submoduleSection)
	for _, sub := range s.Subsections {
		m := &Submodule{}
		m.unmarshal(sub)

		if m.Validate() == ErrModuleBadPath {
			continue
		}

		submodules[m.Name] = m
	}
}

func (c *Config) unmarshalBranches() error {
	bs := c.Raw.Section(branchSection)
	for _, sub := range bs.Subsections {
		b := &Branch{}

		if err := b.unmarshal(sub); err != nil {
			return err
		}

		c.Branches[b.Name] = b
	}
	return nil
}

// Marshal returns Config encoded as a git-config file.
func (c *Config) Marshal() ([]byte, error) {
	c.marshalCore()
	c.marshalPack()
	c.marshalRemotes()
	c.marshalSubmodules()
	c.marshalBranches()

	buf := bytes.NewBuffer(nil)
	if err := format.NewEncoder(buf).Encode(c.Raw); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (c *Config) marshalCore() {
	s := c.Raw.Section(coreSection)
	s.SetOption(bareKey, fmt.Sprintf("%t", c.Core.IsBare))

	if c.Core.Worktree != "" {
		s.SetOption(worktreeKey, c.Core.Worktree)
	}
}

func (c *Config) marshalPack() {
	s := c.Raw.Section(packSection)
	if c.Pack.Window != DefaultPackWindow {
		s.SetOption(windowKey, fmt.Sprintf("%d", c.Pack.Window))
	}
}

func (c *Config) marshalRemotes() {
	s := c.Raw.Section(remoteSection)
	newSubsections := make(format.Subsections, 0, len(c.Remotes))
	added := make(map[string]bool)
	for _, subsection := range s.Subsections {
		if remote, ok := c.Remotes[subsection.Name]; ok {
			newSubsections = append(newSubsections, remote.marshal())
			added[subsection.Name] = true
		}
	}

	remoteNames := make([]string, 0, len(c.Remotes))
	for name := range c.Remotes {
		remoteNames = append(remoteNames, name)
	}

	sort.Strings(remoteNames)

	for _, name := range remoteNames {
		if !added[name] {
			newSubsections = append(newSubsections, c.Remotes[name].marshal())
		}
	}

	s.Subsections = newSubsections
}

func (c *Config) marshalSubmodules() {
	s := c.Raw.Section(submoduleSection)
	s.Subsections = make(format.Subsections, len(c.Submodules))

	var i int
	for _, r := range c.Submodules {
		section := r.marshal()
		// the submodule section at config is a subset of the .gitmodule file
		// we should remove the non-valid options for the config file.
		section.RemoveOption(pathKey)
		s.Subsections[i] = section
		i++
	}
}

func (c *Config) marshalBranches() {
	s := c.Raw.Section(branchSection)
	newSubsections := make(format.Subsections, 0, len(c.Branches))
	added := make(map[string]bool)
	for _, subsection := range s.Subsections {
		if branch, ok := c.Branches[subsection.Name]; ok {
			newSubsections = append(newSubsections, branch.marshal())
			added[subsection.Name] = true
		}
	}

	branchNames := make([]string, 0, len(c.Branches))
	for name := range c.Branches {
		branchNames = append(branchNames, name)
	}

	sort.Strings(branchNames)

	for _, name := range branchNames {
		if !added[name] {
			newSubsections = append(newSubsections, c.Branches[name].marshal())
		}
	}

	s.Subsections = newSubsections
}

// RemoteConfig contains the configuration for a given remote repository.
type RemoteConfig struct {
	// Name of the remote
	Name string
	// URLs the URLs of a remote repository. It must be non-empty. Fetch will
	// always use the first URL, while push will use all of them.
	URLs []string
	// Fetch the default set of "refspec" for fetch operation
	Fetch []RefSpec

	// raw representation of the subsection, filled by marshal or unmarshal are
	// called
	raw *format.Subsection
}

// Validate validates the fields and sets the default values.
func (c *RemoteConfig) Validate() error {
	if c.Name == "" {
		return ErrRemoteConfigEmptyName
	}

	if len(c.URLs) == 0 {
		return ErrRemoteConfigEmptyURL
	}

	for _, r := range c.Fetch {
		if err := r.Validate(); err != nil {
			return err
		}
	}

	if len(c.Fetch) == 0 {
		c.Fetch = []RefSpec{RefSpec(fmt.Sprintf(DefaultFetchRefSpec, c.Name))}
	}

	return nil
}

func (c *RemoteConfig) unmarshal(s *format.Subsection) error {
	c.raw = s

	fetch := []RefSpec{}
	for _, f := range c.raw.Options.GetAll(fetchKey) {
		rs := RefSpec(f)
		if err := rs.Validate(); err != nil {
			return err
		}

		fetch = append(fetch, rs)
	}

	c.Name = c.raw.Name
	c.URLs = append([]string(nil), c.raw.Options.GetAll(urlKey)...)
	c.Fetch = fetch

	return nil
}

func (c *RemoteConfig) marshal() *format.Subsection {
	if c.raw == nil {
		c.raw = &format.Subsection{}
	}

	c.raw.Name = c.Name
	if len(c.URLs) == 0 {
		c.raw.RemoveOption(urlKey)
	} else {
		c.raw.SetOption(urlKey, c.URLs...)
	}

	if len(c.Fetch) == 0 {
		c.raw.RemoveOption(fetchKey)
	} else {
		var values []string
		for _, rs := range c.Fetch {
			values = append(values, rs.String())
		}

		c.raw.SetOption(fetchKey, values...)
	}

	return c.raw
}

func (c *RemoteConfig) IsFirstURLLocal() bool {
	return url.IsLocalEndpoint(c.URLs[0])
}
