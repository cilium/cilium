# Get Runner IP

This composite action fetches the runner public IP address from a provided `source` URL, parses the response (as text or JSON), validates it looks like an IP address, and returns it as an output.

## Inputs

- **`source`** (required)

  URL to fetch the runner public IP from.

- **`parsing`** (optional, default: `text`)

  Parsing mode for the fetched response.

  Supported values:

  - `text`: treat the response body as the IP address (after trimming)
  - `json`: parse the response body as JSON and extract an IP field

- **`json-key`** (optional)

  When `parsing: json`, an optional dot-separated key path used to extract the IP address from the parsed JSON.

  If not set, the action attempts common keys:

  - `ip`
  - `origin`
  - `query`
  - `address`
  - `data.ip`
  - `data.address`

## Outputs

- **`ip`**

  The parsed and validated runner public IP address.

- **`mask`**

  The parsed and validated runner public IP mask.

- **`cidr`**

  The parsed and validated runner public IP in CIDR notation.

## Examples

### Parse plain text

```yaml
- name: Get runner IP
  id: runner-ip
  uses: ./.github/actions/get-runner-ip
  with:
    source: https://api.ipify.org
    parsing: text

- name: Print
  run: |
    echo "Runner IP: ${{ steps.runner-ip.outputs.ip }}"
    echo "Runner Mask: ${{ steps.runner-ip.outputs.mask }}"
    echo "Runner CIDR: ${{ steps.runner-ip.outputs.cidr }}"
```

### Parse JSON using a known key

```yaml
- name: Get runner IP
  id: runner-ip
  uses: ./.github/actions/get-runner-ip
  with:
    source: https://httpbin.org/ip
    parsing: json
    json-key: origin
```

## Behavior and error handling

- The action fails if:

  - `source` is empty
  - the HTTP request fails or returns a non-2xx response
  - `parsing: json` is selected but the response is not valid JSON
  - no IP-like value can be extracted
  - the extracted value does not look like an IPv4 or IPv6 address
