// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package config

import (
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/hubble/cmd/common/config"
)

func newSetCommand(vp *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "set KEY [VALUE]",
		Short: "Set an individual value in the hubble config file",
		Long: "Set an individual value in the hubble config file.\n" +
			"If VALUE is not provided, the value is reset to its default value.",
		ValidArgs: vp.AllKeys(),
		RunE: func(cmd *cobra.Command, args []string) error {
			var val string
			switch len(args) {
			case 2:
				val = args[1]
				fallthrough
			case 1:
				return runSet(cmd, vp, args[0], val)
			default:
				return fmt.Errorf("invalid arguments: set requires exactly 1 or 2 argument(s): got '%s'", strings.Join(args, " "))
			}
		},
	}
}

func runSet(cmd *cobra.Command, vp *viper.Viper, key, value string) error {
	if !isKey(vp, key) {
		return fmt.Errorf("unknown key: %s", key)
	}

	// each viper key/value entry should be bound to a command flag
	flag := cmd.Flag(key)
	if flag == nil {
		return fmt.Errorf("key=%s not bound to a flag", key)
	}

	val := value
	if value == "" {
		val = flag.DefValue
	}

	var err error
	var newVal any
	typ := flag.Value.Type()
	switch typ {
	case "bool":
		newVal, err = cast.ToBoolE(val)
	case "duration":
		newVal, err = cast.ToDurationE(val)
	case "int":
		newVal, err = cast.ToIntE(val)
	case "string":
		newVal = val
	case "stringSlice":
		val = strings.TrimSuffix(strings.TrimPrefix(val, "["), "]")
		if val == "" {
			newVal = []string{} // csv reader would return io.EOF
		} else {
			newVal, err = csv.NewReader(strings.NewReader(val)).Read()
		}
	default:
		return fmt.Errorf("unhandeld type %s, please open an issue", typ)
	}
	if err != nil {
		return fmt.Errorf("cannot assign value=%s for key=%s, expected type=%s: %w", value, key, typ, err)
	}

	// Create a file-only viper config from the configured file to avoid
	// writing defaults and/or values set via environment variables or flags.
	// This viper config is only used to write the resulting config.
	// This method also prevents from writing default values for all keys
	// therefore only writing key/value pairs explicitly set by the caller.
	configPath := vp.GetString(config.KeyConfig)
	fileVP, err := newFileOnlyViper(configPath)
	if err != nil {
		return err
	}
	fileVP.Set(key, newVal)
	return fileVP.WriteConfigAs(configPath)
}

// newFileOnlyViper creates a new viper config that only reads from the given
// configuration file and is not bound to any environment variable or flag.
func newFileOnlyViper(configPath string) (*viper.Viper, error) {
	if configPath == "" {
		return nil, errors.New("config file undefined")
	}

	path := filepath.Clean(configPath)
	base := filepath.Base(path)
	ext := filepath.Ext(path)

	dir := filepath.Dir(path)
	filename := strings.TrimSuffix(base, ext)
	typ := strings.TrimPrefix(ext, ".")

	vp := viper.New()
	vp.SetConfigName(filename)
	vp.SetConfigType(typ)
	vp.AddConfigPath(dir)

	// Ensure that the configuration directory exists as viper does not create
	// the directory fo the configuration file if it doesn't already exist.
	// (note: MkdirAll does nothing if it exists already)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("configuration directory does not exist and cannot be created: %w", err)
	}

	if err := vp.ReadInConfig(); err != nil {
		// it's OK so long as the failure is ConfigFileNotFound
		// for all other cases, failing to read the config should be an error
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return nil, err
		}
	}
	return vp, nil
}
