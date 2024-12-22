// Package netutil contains common utilities for IP, MAC, and other kinds of
// network addresses.
package netutil

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Potterli20/golibs-fork/errors"
	"golang.org/x/net/idna"
)

// Various Network Address Utilities

// CloneURL returns a deep clone of u.  The User pointer of clone is the same,
// since a *url.Userinfo is effectively an immutable value.
func CloneURL(u *url.URL) (clone *url.URL) {
	if u == nil {
		return nil
	}

	cloneVal := *u

	return &cloneVal
}

// IsValidHostInnerRune returns true if r is a valid inner—that is, neither
// initial nor final—rune for a hostname label.
func IsValidHostInnerRune(r rune) (ok bool) {
	return r == '-' || IsValidHostOuterRune(r)
}

// IsValidHostOuterRune returns true if r is a valid initial or final rune for
// a hostname label.
func IsValidHostOuterRune(r rune) (ok bool) {
	switch {
	case
		r >= 'a' && r <= 'z',
		r >= 'A' && r <= 'Z',
		r >= '0' && r <= '9':
		return true
	default:
		return false
	}
}

// JoinHostPort is a convenient wrapper for net.JoinHostPort with port of type
// uint16.  As opposed to net.JoinHostPort it also trims the host from square
// brackets if any.  This may be useful when passing url.URL.Host field
// containing an IPv6 address.
func JoinHostPort(host string, port uint16) (hostport string) {
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.FormatUint(uint64(port), 10))
}

// SplitHostPort is a convenient wrapper for [net.SplitHostPort] with port of
// type uint16.
func SplitHostPort(hostport string) (host string, port uint16, err error) {
	var portStr string
	host, portStr, err = net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}

	var portUint uint64
	portUint, err = strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parsing port: %w", err)
	}

	return host, uint16(portUint), nil
}

// SplitHost is a wrapper for [net.SplitHostPort] for cases when the hostport
// may or may not contain a port.
func SplitHost(hostport string) (host string, err error) {
	host, _, err = net.SplitHostPort(hostport)
	if err != nil {
		// Check for the missing port error.  If it is that error, just
		// use the host as is.
		//
		// See the source code for net.SplitHostPort.
		const missingPort = "missing port in address"

		addrErr := &net.AddrError{}
		if !errors.As(err, &addrErr) || addrErr.Err != missingPort {
			return "", err
		}

		host = hostport
	}

	return host, nil
}

// Subdomains returns all subdomains of domain, starting from domain itself.
// domain must be a valid, non-fully-qualified domain name.  If domain is empty,
// Subdomains returns nil.
func Subdomains(domain string) (sub []string) {
	if domain == "" {
		return nil
	}

	sub = []string{domain}

	for domain != "" {
		i := strings.IndexByte(domain, '.')
		if i < 0 {
			break
		}

		domain = domain[i+1:]
		sub = append(sub, domain)
	}

	return sub
}

// IsSubdomain returns true if domain is a subdomain of top.  domain and top
// should be valid domain names, qualified in the same manner, and have the same
// letter case.
func IsSubdomain(domain, top string) (ok bool) {
	// TODO(a.garipov): Use stringutil.HasSuffixFold when it is added.
	return len(domain) > len(top)+1 &&
		strings.HasSuffix(domain, top) &&
		domain[len(domain)-len(top)-1] == '.'
}

// IsImmediateSubdomain returns true if domain is an immediate subdomain of top.
// domain and top should be valid domain names, qualified in the same manner,
// and have the same letter case.
func IsImmediateSubdomain(domain, top string) (ok bool) {
	return IsSubdomain(domain, top) && strings.Count(domain, ".") == strings.Count(top, ".")+1
}

// ValidateMAC returns an error if mac is not a valid EUI-48, EUI-64, or
// 20-octet InfiniBand link-layer address.
//
// Any error returned will have the underlying type of [*AddrError].
func ValidateMAC(mac net.HardwareAddr) (err error) {
	defer makeAddrError(&err, mac.String(), AddrKindMAC)

	switch l := len(mac); l {
	case 0:
		return &LengthError{
			Kind:   AddrKindMAC,
			Length: 0,
		}
	case 6, 8, 20:
		return nil
	default:
		return &LengthError{
			Kind:    AddrKindMAC,
			Allowed: []int{6, 8, 20},
			Length:  l,
		}
	}
}

// MaxDomainLabelLen is the maximum allowed length of a domain name label
// according to [RFC 1035].
//
// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
const MaxDomainLabelLen = 63

// ValidateTLDLabel validates the top-level domain label in accordance to [RFC
// 3696 Section 2].  In addition to the validations performed by
// [ValidateHostnameLabel], it also checks that the label contains at least one
// non-digit character.
//
// Any error returned will have the underlying type of [*LabelError].
//
// [RFC 3696 Section 2]: https://datatracker.ietf.org/doc/html/rfc3696#section-2
func ValidateTLDLabel(tld string) (err error) {
	defer makeLabelError(&err, tld, LabelKindTLD)

	if err = ValidateHostnameLabel(tld); err != nil {
		err = errors.Unwrap(err)
		replaceKind(err, LabelKindTLD)

		return err
	}

	for _, r := range tld {
		if r < '0' || r > '9' {
			return nil
		}
	}

	// There is a requirement for top-level domain label to contain at least one
	// non-digit character.  See [RFC 3696 Section 2].
	//
	// [RFC 3696 Section 2]: https://datatracker.ietf.org/doc/html/rfc3696#section-2
	return errors.Error("all octets are numeric")
}

// MaxDomainNameLen is the maximum allowed length of a full domain name
// according to [RFC 1035].
//
// See also: https://stackoverflow.com/a/32294443/1892060.
//
// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
const MaxDomainNameLen = 253

// ValidateDomainName validates the domain name in accordance to [RFC 1035] and
// [RFC 3696 Section 2].  As opposed to [ValidateHostname], this function only
// validates the lengths of the name itself and its labels, except the TLD.
//
// Any error returned will have the underlying type of [*AddrError].
//
// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
// [RFC 3696 Section 2]: https://datatracker.ietf.org/doc/html/rfc3696#section-2
func ValidateDomainName(name string) (err error) {
	defer makeAddrError(&err, name, AddrKindDomainName)

	name, err = idna.ToASCII(name)
	if err != nil {
		return err
	}

	if name == "" {
		return &LengthError{
			Kind:   AddrKindDomainName,
			Length: 0,
		}
	} else if l := len(name); l > MaxDomainNameLen {
		return &LengthError{
			Kind:   AddrKindDomainName,
			Max:    MaxDomainNameLen,
			Length: l,
		}
	}

	label, tail, found := strings.Cut(name, ".")
	for ; found; label, tail, found = strings.Cut(tail, ".") {
		err = ValidateDomainNameLabel(label)
		if err != nil {
			return err
		}
	}

	// Use stricter rules for the TLD.
	return ValidateTLDLabel(label)
}

// ValidateDomainNameLabel returns an error if label is not a valid label of a
// domain name.  An empty label is considered invalid.  Essentially it validates
// the length of the label since the name in DNS is permitted to contain any
// printable ASCII character, see [RFC 3696 Section 2].  label must only contain
// ASCII characters, see [idna.ToASCII].
//
// Any error returned will have the underlying type of [*LabelError].
//
// [RFC 3696 Section 2]: https://datatracker.ietf.org/doc/html/rfc3696#section-2
func ValidateDomainNameLabel(label string) (err error) {
	defer makeLabelError(&err, label, LabelKindDomain)

	if label == "" {
		return &LengthError{
			Kind:   LabelKindDomain,
			Length: 0,
		}
	}

	l := len(label)
	if l > MaxDomainLabelLen {
		return &LengthError{
			Kind:   LabelKindDomain,
			Max:    MaxDomainLabelLen,
			Length: l,
		}
	}

	return nil
}

// ValidateHostnameLabel returns an error if label is not a valid label of a
// domain name.  An empty label is considered invalid.
//
// Any error returned will have the underlying type of [*LabelError].
func ValidateHostnameLabel(label string) (err error) {
	defer makeLabelError(&err, label, LabelKindHost)

	if err = ValidateDomainNameLabel(label); err != nil {
		err = errors.Unwrap(err)
		replaceKind(err, LabelKindHost)

		return err
	}

	l := len(label)
	if r := rune(label[0]); !IsValidHostOuterRune(r) {
		return &RuneError{
			Kind: LabelKindHost,
			Rune: r,
		}
	} else if l == 1 {
		return nil
	}

	for _, r := range label[1 : l-1] {
		if !IsValidHostInnerRune(r) {
			return &RuneError{
				Kind: LabelKindHost,
				Rune: r,
			}
		}
	}

	if r := rune(label[l-1]); !IsValidHostOuterRune(r) {
		return &RuneError{
			Kind: LabelKindHost,
			Rune: r,
		}
	}

	return nil
}

// ValidateHostname validates the domain name in accordance to [RFC 952], [RFC
// 1035], and with [RFC 1123]'s inclusion of digits at the start of the host.
// It doesn't validate against two or more hyphens to allow punycode and
// internationalized domains.
//
// Any error returned will have the underlying type of [*AddrError].
//
// [RFC 952]: https://datatracker.ietf.org/doc/html/rfc952
// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
// [RFC 1123]: https://datatracker.ietf.org/doc/html/rfc1123
func ValidateHostname(name string) (err error) {
	defer makeAddrError(&err, name, AddrKindName)

	name, err = idna.ToASCII(name)
	if err != nil {
		return err
	}

	if name == "" {
		return &LengthError{
			Kind:   AddrKindName,
			Length: 0,
		}
	} else if l := len(name); l > MaxDomainNameLen {
		return &LengthError{
			Kind:   AddrKindName,
			Max:    MaxDomainNameLen,
			Length: l,
		}
	}

	label, tail, found := strings.Cut(name, ".")
	for ; found; label, tail, found = strings.Cut(tail, ".") {
		err = ValidateHostnameLabel(label)
		if err != nil {
			return err
		}
	}

	return ValidateTLDLabel(label)
}

// MaxServiceLabelLen is the maximum allowed length of a service name label
// according to [RFC 6335].
//
// [RFC 6335]: https://datatracker.ietf.org/doc/html/rfc6335
const MaxServiceLabelLen = 16

// ValidateServiceNameLabel returns an error if label is not a valid label of
// a service domain name.  An empty label is considered invalid.
//
// Any error returned will have the underlying type of [*LabelError].
func ValidateServiceNameLabel(label string) (err error) {
	defer makeLabelError(&err, label, LabelKindSRV)

	if label == "" || label == "_" {
		return &LengthError{
			Kind:   LabelKindSRV,
			Length: 0,
		}
	} else if r := rune(label[0]); r != '_' {
		return &RuneError{
			Kind: LabelKindSRV,
			Rune: r,
		}
	}

	l := len(label)
	if l > MaxServiceLabelLen {
		return &LengthError{
			Kind:   LabelKindSRV,
			Max:    MaxServiceLabelLen,
			Length: l,
		}
	}

	// TODO(e.burkov):  Validate adjacent hyphens since service labels can't be
	// internationalized.  See RFC 6336 Section 5.1.
	if err = ValidateHostnameLabel(label[1:]); err != nil {
		err = errors.Unwrap(err)
		replaceKind(err, LabelKindSRV)

		return err
	}

	return nil
}

// ValidateSRVDomainName validates name assuming it belongs to the superset of
// service domain names in accordance to [RFC 2782] and [RFC 6763].  It doesn't
// validate against two or more hyphens to allow punycode and internationalized
// domains.
//
// Any error returned will have the underlying type of [*AddrError].
//
// [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782
// [RFC 6763]: https://datatracker.ietf.org/doc/html/rfc6763
func ValidateSRVDomainName(name string) (err error) {
	defer makeAddrError(&err, name, AddrKindSRVName)

	name, err = idna.ToASCII(name)
	if err != nil {
		return err
	}

	if name == "" {
		return &LengthError{
			Kind:   AddrKindSRVName,
			Length: 0,
		}
	} else if l := len(name); l > MaxDomainNameLen {
		return &LengthError{
			Kind:   AddrKindSRVName,
			Max:    MaxDomainNameLen,
			Length: l,
		}
	}

	label, tail, found := strings.Cut(name, ".")
	for ; found; label, tail, found = strings.Cut(tail, ".") {
		if strings.HasPrefix(label, "_") {
			err = ValidateServiceNameLabel(label)
		} else {
			err = ValidateHostnameLabel(label)
		}
		if err != nil {
			return err
		}
	}

	return ValidateTLDLabel(label)
}
