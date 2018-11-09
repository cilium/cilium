package external

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/internal/ini"
)

const (
	// Static Credentials group
	accessKeyIDKey  = `aws_access_key_id`     // group required
	secretAccessKey = `aws_secret_access_key` // group required
	sessionTokenKey = `aws_session_token`     // optional

	// Assume Role Credentials group
	roleArnKey         = `role_arn`          // group required
	sourceProfileKey   = `source_profile`    // group required
	externalIDKey      = `external_id`       // optional
	mfaSerialKey       = `mfa_serial`        // optional
	roleSessionNameKey = `role_session_name` // optional

	// Additional Config fields
	regionKey = `region`
)

// DefaultSharedConfigProfile is the default profile to be used when
// loading configuration from the config files if another profile name
// is not provided.
var DefaultSharedConfigProfile = `default`

// DefaultSharedCredentialsFilename returns the SDK's default file path
// for the shared credentials file.
//
// Builds the shared config file path based on the OS's platform.
//
//   - Linux/Unix: $HOME/.aws/credentials
//   - Windows: %USERPROFILE%\.aws\credentials
func DefaultSharedCredentialsFilename() string {
	return filepath.Join(userHomeDir(), ".aws", "credentials")
}

// DefaultSharedConfigFilename returns the SDK's default file path for
// the shared config file.
//
// Builds the shared config file path based on the OS's platform.
//
//   - Linux/Unix: $HOME/.aws/config
//   - Windows: %USERPROFILE%\.aws\config
func DefaultSharedConfigFilename() string {
	return filepath.Join(userHomeDir(), ".aws", "config")
}

// DefaultSharedConfigFiles is a slice of the default shared config files that
// the will be used in order to load the SharedConfig.
var DefaultSharedConfigFiles = []string{
	DefaultSharedCredentialsFilename(),
	DefaultSharedConfigFilename(),
}

// AssumeRoleConfig provides the values defining the configuration for an IAM
// assume role.
type AssumeRoleConfig struct {
	RoleARN         string
	ExternalID      string
	MFASerial       string
	RoleSessionName string

	sourceProfile string
	Source        *SharedConfig
}

// SharedConfig represents the configuration fields of the SDK config files.
type SharedConfig struct {
	Profile string

	// Credentials values from the config file. Both aws_access_key_id
	// and aws_secret_access_key must be provided together in the same file
	// to be considered valid. The values will be ignored if not a complete group.
	// aws_session_token is an optional field that can be provided if both of the
	// other two fields are also provided.
	//
	//	aws_access_key_id
	//	aws_secret_access_key
	//	aws_session_token
	Credentials aws.Credentials

	AssumeRole AssumeRoleConfig

	// Region is the region the SDK should use for looking up AWS service endpoints
	// and signing requests.
	//
	//	region
	Region string
}

// GetRegion returns the region for the profile if a region is set.
func (c SharedConfig) GetRegion() (string, error) {
	return c.Region, nil
}

// GetCredentialsValue returns the credentials for a profile if they were set.
func (c SharedConfig) GetCredentialsValue() (aws.Credentials, error) {
	return c.Credentials, nil
}

// GetAssumeRoleConfig returns the assume role config for a profile. Will be
// a zero value if not set.
func (c SharedConfig) GetAssumeRoleConfig() (AssumeRoleConfig, error) {
	return c.AssumeRole, nil
}

// LoadSharedConfigIgnoreNotExist is an alias for LoadSharedConfig with the
// addition of ignoring when none of the files exist or when the profile
// is not found in any of the files.
func LoadSharedConfigIgnoreNotExist(configs Configs) (Config, error) {
	cfg, err := LoadSharedConfig(configs)
	if err != nil {
		if _, ok := err.(SharedConfigNotExistErrors); ok {
			return SharedConfig{}, nil
		}
		return nil, err
	}

	return cfg, nil
}

// LoadSharedConfig uses the Configs passed in to load the SharedConfig from file
// The file names and profile name are sourced from the Configs.
//
// If profile name is not provided DefaultSharedConfigProfile (default) will
// be used.
//
// If shared config filenames are not provided DefaultSharedConfigFiles will
// be used.
//
// Config providers used:
// * SharedConfigProfileProvider
// * SharedConfigFilesProvider
func LoadSharedConfig(configs Configs) (Config, error) {
	var profile string
	var files []string
	var ok bool
	var err error

	profile, ok, err = GetSharedConfigProfile(configs)
	if err != nil {
		return nil, err
	}
	if !ok {
		profile = DefaultSharedConfigProfile
	}

	files, ok, err = GetSharedConfigFiles(configs)
	if err != nil {
		return nil, err
	}
	if !ok {
		files = DefaultSharedConfigFiles
	}

	return NewSharedConfig(profile, files)
}

// NewSharedConfig retrieves the configuration from the list of files
// using the profile provided. The order the files are listed will determine
// precedence. Values in subsequent files will overwrite values defined in
// earlier files.
//
// For example, given two files A and B. Both define credentials. If the order
// of the files are A then B, B's credential values will be used instead of A's.
func NewSharedConfig(profile string, filenames []string) (SharedConfig, error) {
	if len(filenames) == 0 {
		return SharedConfig{}, fmt.Errorf("no shared config files provided")
	}

	files, err := loadSharedConfigIniFiles(filenames)
	if err != nil {
		return SharedConfig{}, err
	}

	cfg := SharedConfig{}
	if err = cfg.setFromIniFiles(profile, files); err != nil {
		return SharedConfig{}, err
	}

	if len(cfg.AssumeRole.sourceProfile) > 0 {
		if err := cfg.setAssumeRoleSource(profile, files); err != nil {
			return SharedConfig{}, err
		}
	}

	return cfg, nil
}

type sharedConfigFile struct {
	Filename string
	IniData  ini.Sections
}

func loadSharedConfigIniFiles(filenames []string) ([]sharedConfigFile, error) {
	files := make([]sharedConfigFile, 0, len(filenames))

	errs := SharedConfigNotExistErrors{}
	for _, filename := range filenames {
		sections, err := ini.OpenFile(filename)
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == ini.ErrCodeUnableToReadFile {
			errs = append(errs,
				SharedConfigFileNotExistError{Filename: filename, Err: err},
			)
			// Skip files which can't be opened and read for whatever reason
			continue
		} else if err != nil {
			return nil, SharedConfigLoadError{Filename: filename, Err: err}
		}

		files = append(files, sharedConfigFile{
			Filename: filename, IniData: sections,
		})
	}

	if len(files) == 0 {
		return nil, errs
	}

	return files, nil
}

func (c *SharedConfig) setAssumeRoleSource(origProfile string, files []sharedConfigFile) error {
	var assumeRoleSrc SharedConfig

	// Multiple level assume role chains are not support
	if c.AssumeRole.sourceProfile == origProfile {
		assumeRoleSrc = *c
		assumeRoleSrc.AssumeRole = AssumeRoleConfig{}
	} else {
		err := assumeRoleSrc.setFromIniFiles(c.AssumeRole.sourceProfile, files)
		if err != nil {
			return SharedConfigAssumeRoleError{
				Profile: c.Profile,
				RoleARN: c.AssumeRole.RoleARN,
				Err:     err,
			}
		}
	}

	if len(assumeRoleSrc.Credentials.AccessKeyID) == 0 {
		return SharedConfigAssumeRoleError{
			Profile: c.Profile,
			RoleARN: c.AssumeRole.RoleARN,
			Err:     fmt.Errorf("source profile has no shared credentials"),
		}
	}

	c.AssumeRole.Source = &assumeRoleSrc

	return nil
}

// Returns an error if all of the files fail to load. If at least one file is
// successfully loaded and contains the profile, no error will be returned.
func (c *SharedConfig) setFromIniFiles(profile string, files []sharedConfigFile) error {
	c.Profile = profile

	existErrs := SharedConfigNotExistErrors{}
	for _, f := range files {
		if err := c.setFromIniFile(profile, f); err != nil {
			if _, ok := err.(SharedConfigProfileNotExistError); ok {
				existErrs = append(existErrs, err)
				continue
			}
			return err
		}
	}

	if len(existErrs) == len(files) {
		return existErrs
	}

	return nil
}

// setFromFile loads the configuration from the file using
// the profile provided. A SharedConfig pointer type value is used so that
// multiple config file loadings can be chained.
//
// Only loads complete logically grouped values, and will not set fields in cfg
// for incomplete grouped values in the config. Such as credentials. For example
// if a config file only includes aws_access_key_id but no aws_secret_access_key
// the aws_access_key_id will be ignored.
func (c *SharedConfig) setFromIniFile(profile string, file sharedConfigFile) error {
	section, ok := file.IniData.GetSection(profile)
	if !ok {
		// Fallback to to alternate profile name: profile <name>
		section, ok = file.IniData.GetSection(fmt.Sprintf("profile %s", profile))
		if !ok {
			return SharedConfigProfileNotExistError{
				Filename: file.Filename,
				Profile:  profile,
				Err:      nil,
			}
		}
	}

	// Shared Credentials
	akid := section.String(accessKeyIDKey)
	secret := section.String(secretAccessKey)
	if len(akid) > 0 && len(secret) > 0 {
		c.Credentials = aws.Credentials{
			AccessKeyID:     akid,
			SecretAccessKey: secret,
			SessionToken:    section.String(sessionTokenKey),
			Source:          fmt.Sprintf("SharedConfigCredentials: %s", file.Filename),
		}
	}

	// Assume Role
	roleArn := section.String(roleArnKey)
	srcProfile := section.String(sourceProfileKey)
	if len(roleArn) > 0 && len(srcProfile) > 0 {
		c.AssumeRole = AssumeRoleConfig{
			RoleARN:         roleArn,
			ExternalID:      section.String(externalIDKey),
			MFASerial:       section.String(mfaSerialKey),
			RoleSessionName: section.String(roleSessionNameKey),

			sourceProfile: srcProfile,
		}
	}

	// Region
	if v := section.String(regionKey); len(v) > 0 {
		c.Region = v
	}

	return nil
}

// SharedConfigNotExistErrors provides an error type for failure to load shared
// config because resources do not exist.
type SharedConfigNotExistErrors []error

func (es SharedConfigNotExistErrors) Error() string {
	msg := "failed to load shared config\n"
	for _, e := range es {
		msg += "\t" + e.Error()
	}
	return msg
}

// SharedConfigLoadError is an error for the shared config file failed to load.
type SharedConfigLoadError struct {
	Filename string
	Err      error
}

// Cause is the underlying error that caused the failure.
func (e SharedConfigLoadError) Cause() error {
	return e.Err
}

func (e SharedConfigLoadError) Error() string {
	return fmt.Sprintf("failed to load shared config file, %s, %v", e.Filename, e.Err)
}

// SharedConfigFileNotExistError is an error for the shared config when
// the filename does not exist.
type SharedConfigFileNotExistError struct {
	Filename string
	Profile  string
	Err      error
}

// Cause is the underlying error that caused the failure.
func (e SharedConfigFileNotExistError) Cause() error {
	return e.Err
}

func (e SharedConfigFileNotExistError) Error() string {
	return fmt.Sprintf("failed to open shared config file, %s, %v", e.Filename, e.Err)
}

// SharedConfigProfileNotExistError is an error for the shared config when
// the profile was not find in the config file.
type SharedConfigProfileNotExistError struct {
	Filename string
	Profile  string
	Err      error
}

// Cause is the underlying error that caused the failure.
func (e SharedConfigProfileNotExistError) Cause() error {
	return e.Err
}

func (e SharedConfigProfileNotExistError) Error() string {
	return fmt.Sprintf("failed to get shared config profile, %s, in %s, %v", e.Profile, e.Filename, e.Err)
}

// SharedConfigAssumeRoleError is an error for the shared config when the
// profile contains assume role information, but that information is invalid
// or not complete.
type SharedConfigAssumeRoleError struct {
	Profile string
	RoleARN string
	Err     error
}

func (e SharedConfigAssumeRoleError) Error() string {
	return fmt.Sprintf("failed to load assume role %s, of profile %s, %v",
		e.RoleARN, e.Profile, e.Err)
}

func userHomeDir() string {
	if runtime.GOOS == "windows" { // Windows
		return os.Getenv("USERPROFILE")
	}

	// *nix
	return os.Getenv("HOME")
}
