package tpl

const strTpl = `
	{{ $f := .Field }}{{ $r := .Rules }}
	{{ template "const" . }}
	{{ template "in" . }}
	{{ if $r.Pattern }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement regular expression constraints.
		if !{{ lookup $f "Pattern" }}.MatchString({{ accessor . }}) {
			return {{ err . "value does not match regex pattern " (lit $r.GetPattern) }}
		}
		*/}}
	{{ end }}
	{{ if $r.Prefix }}
	{
		const std::string prefix = {{ lit $r.GetPrefix }};
		if (!pgv::IsPrefix(prefix, {{ accessor . }})) {
			{{ err . "value does not have prefix " (lit $r.GetPrefix) }}
		}
	}
	{{ end }}

	{{ if $r.Suffix }}
	{
		const std::string suffix = {{ lit $r.GetSuffix }};
		const std::string& value = {{ accessor . }};
		if (!pgv::IsSuffix(suffix, value)) {
			{{ err . "value does not have suffix " (lit $r.GetSuffix) }}
		}
	}
	{{ end }}

	{{ if $r.Contains }}
	{
		if (!pgv::Contains({{ accessor . }}, {{ lit $r.GetContains }})) {
			{{ err . "value does not contain substring " (lit $r.GetContains) }}
		}
	}
	{{ end }}

	{{ if $r.GetIp }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement IP address constraints
		if ip := net.ParseIP({{ accessor . }}); ip == nil {
			return {{ err . "value must be a valid IP address" }}
		}
		*/}}
	{{ else if $r.GetIpv4 }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement IP address constraints
		if ip := net.ParseIP({{ accessor . }}); ip == nil || ip.To4() == nil {
			return {{ err . "value must be a valid IPv4 address" }}
		}
		*/}}
	{{ else if $r.GetIpv6 }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement IP address constraints
		if ip := net.ParseIP({{ accessor . }}); ip == nil || ip.To4() != nil {
			return {{ err . "value must be a valid IPv6 address" }}
		}
		*/}}
	{{ else if $r.GetEmail }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement email address constraints
		if err := m._validateEmail({{ accessor . }}); err != nil {
			return {{ errCause . "err" "value must be a valid email address" }}
		}
		*/}}
	{{ else if $r.GetHostname }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement hostname constraints
		if err := m._validateHostname({{ accessor . }}); err != nil {
			return {{ errCause . "err" "value must be a valid hostname" }}
		}
		*/}}
	{{ else if $r.GetUri }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement URI constraints
		if uri, err := url.Parse({{ accessor . }}); err != nil {
			return {{ errCause . "err" "value must be a valid URI" }}
		} else if !uri.IsAbs() {
			return {{ err . "value must be absolute" }}
		}
		*/}}
	{{ else if $r.GetUriRef }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement URI constraints
		if _, err := url.Parse({{ accessor . }}); err != nil {
			return {{ errCause . "err" "value must be a valid URI" }}
		}
		*/}}
	{{ end }}

	{{ if $r.MinLen }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement UTF-8 length constraints
		{{ if $r.MaxLen }}
			{{ if eq $r.GetMinLen $r.GetMaxLen }}
				if utf8.RuneCountInString({{ accessor . }}) != {{ $r.GetMinLen }} {
					return {{ err . "value length must be " $r.GetMinLen " runes" }}
				}
			{{ else }}
				if l := utf8.RuneCountInString({{ accessor . }}); l < {{ $r.GetMinLen }} || l > {{ $r.GetMaxLen }} {
					return {{ err . "value length must be between " $r.GetMinLen " and " $r.GetMaxLen " runes, inclusive" }}
				}
			{{ end }}
		{{ else }}
			if utf8.RuneCountInString({{ accessor . }}) < {{ $r.GetMinLen }} {
				return {{ err . "value length must be at least " $r.GetMinLen " runes" }}
			}
		{{ end }}
		*/}}
	{{ else if $r.MaxLen }}
		{{ unimplemented }}
		{{/* TODO(akonradi) implement UTF-8 length constraints
		if utf8.RuneCountInString({{ accessor . }}) > {{ $r.GetMaxLen }} {
			return {{ err . "value length must be at most " $r.GetMaxLen " runes" }}
		}
		*/}}
	{{ end }}

	{{ if $r.MinBytes }}
	{
		const auto length = {{ accessor . }}.size();
		{{ if $r.MaxBytes }}
			{{ if eq $r.GetMinBytes $r.GetMaxBytes }}
				if (length != {{ $r.GetMinBytes }}) {
					{{ err . "value length must be " $r.GetMinBytes " bytes" }}
				}
			{{ else }}
				if (length < {{ $r.GetMinBytes }} || length > {{ $r.GetMaxBytes }}) {
					{{ err . "value length must be between " $r.GetMinBytes " and " $r.GetMaxBytes " bytes, inclusive" }}
				}
			{{ end }}
		{{ else }}
			if (length < {{ $r.GetMinBytes }}) {
				{{ err . "value length must be at least " $r.GetMinBytes " bytes" }}
			}
		{{ end }}
	}
	{{ else if $r.MaxBytes }}
		if ({{ accessor . }}.size() > {{ $r.GetMaxBytes }}) {
			{{ err . "value length must be at most " $r.GetMaxBytes " bytes" }}
		}
	{{ end }}
`
