package tpl

const bytesTpl = `
	{{ $f := .Field }}{{ $r := .Rules }}

	{{ if $r.Pattern }}
		if !{{ lookup $f "Pattern" }}.Match({{ accessor . }}) {
			return {{ err . "value does not match regex pattern " (lit $r.GetPattern) }}
		}
	{{ end }}


	{{ if $r.Prefix }}
		if !bytes.HasPrefix({{ accessor . }}, {{ lit $r.GetPrefix }}) {
			return {{ err . "value does not have prefix " (byteStr $r.GetPrefix) }}
		}
	{{ end }}

	{{ if $r.Suffix }}
		if !bytes.HasSuffix({{ accessor . }}, {{ lit $r.GetSuffix }}) {
			return {{ err . "value does not have suffix " (byteStr $r.GetSuffix) }}
		}
	{{ end }}

	{{ if $r.Contains }}
		if !bytes.Contains({{ accessor . }}, {{ lit $r.GetContains }}) {
			return {{ err . "value does not contain " (byteStr $r.GetContains) }}
		}
	{{ end }}

	{{ if $r.MinLen }}
		{{ if $r.MaxLen }}
			{{ if eq $r.GetMinLen $r.GetMaxLen }}
				if len({{ accessor . }}) != {{ $r.GetMinLen }} {
					return {{ err . "value length must be " $r.GetMinLen " bytes" }}
				}
			{{ else }}
				if l := len({{ accessor . }}); l < {{ $r.GetMinLen }} || l > {{ $r.GetMaxLen }} {
					return {{ err . "value length must be between " $r.GetMinLen " and " $r.GetMaxLen " bytes, inclusive" }}
				}
			{{ end }}
		{{ else }}
			if len({{ accessor . }}) < {{ $r.GetMinLen }} {
				return {{ err . "value length must be at least " $r.GetMinLen " bytes" }}
			}
		{{ end }}
	{{ else if $r.MaxLen }}
		if len({{ accessor . }}) > {{ $r.GetMaxLen }} {
			return {{ err . "value length must be at most " $r.GetMaxLen " bytes" }}
		}
	{{ end }}

	{{ if $r.In }}
		if _, ok := {{ lookup $f "InLookup" }}[string({{ accessor . }})]; !ok {
			return {{ err . "value must be in list " $r.In }}
		}
	{{ else if $r.NotIn }}
		if _, ok := {{ lookup $f "NotInLookup" }}[string({{ accessor . }})]; ok {
			return {{ err . "value must not be in list " $r.NotIn }}
		}
	{{ end }}

	{{ if $r.Const }}
		if !bytes.Equal({{ accessor . }}, {{ lit $r.Const }}) {
			return {{ err . "value must equal " $r.Const }}
		}
	{{ end }}

	{{ if $r.GetIp }}
		if ip := net.IP({{ accessor . }}); ip.To16() == nil {
			return {{ err . "value must be a valid IP address" }}
		}
	{{ else if $r.GetIpv4 }}
		if ip := net.IP({{ accessor . }}); ip.To4() == nil {
			return {{ err . "value must be a valid IPv4 address" }}
		}
	{{ else if $r.GetIpv6 }}
		if ip := net.IP({{ accessor . }}); ip.To16() == nil || ip.To4() != nil {
			return {{ err . "value must be a valid IPv6 address" }}
		}
	{{ end }}
`
