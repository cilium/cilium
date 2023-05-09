package ports

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/pagination"
)

// ListOptsBuilder allows extensions to add additional parameters to the
// List request.
type ListOptsBuilder interface {
	ToPortListQuery() (string, error)
}

// ListOpts allows the filtering and sorting of paginated collections through
// the API. Filtering is achieved by passing in struct field values that map to
// the port attributes you want to see returned. SortKey allows you to sort
// by a particular port attribute. SortDir sets the direction, and is either
// `asc' or `desc'. Marker and Limit are used for pagination.
type ListOpts struct {
	Status       string `q:"status"`
	Name         string `q:"name"`
	Description  string `q:"description"`
	AdminStateUp *bool  `q:"admin_state_up"`
	NetworkID    string `q:"network_id"`
	TenantID     string `q:"tenant_id"`
	ProjectID    string `q:"project_id"`
	DeviceOwner  string `q:"device_owner"`
	MACAddress   string `q:"mac_address"`
	ID           string `q:"id"`
	DeviceID     string `q:"device_id"`
	Limit        int    `q:"limit"`
	Marker       string `q:"marker"`
	SortKey      string `q:"sort_key"`
	SortDir      string `q:"sort_dir"`
	Tags         string `q:"tags"`
	TagsAny      string `q:"tags-any"`
	NotTags      string `q:"not-tags"`
	NotTagsAny   string `q:"not-tags-any"`
	FixedIPs     []FixedIPOpts
}

type FixedIPOpts struct {
	IPAddress       string
	IPAddressSubstr string
	SubnetID        string
}

func (f FixedIPOpts) String() string {
	var res []string
	if f.IPAddress != "" {
		res = append(res, fmt.Sprintf("ip_address=%s", f.IPAddress))
	}
	if f.IPAddressSubstr != "" {
		res = append(res, fmt.Sprintf("ip_address_substr=%s", f.IPAddressSubstr))
	}
	if f.SubnetID != "" {
		res = append(res, fmt.Sprintf("subnet_id=%s", f.SubnetID))
	}
	return strings.Join(res, ",")
}

// ToPortListQuery formats a ListOpts into a query string.
func (opts ListOpts) ToPortListQuery() (string, error) {
	q, err := gophercloud.BuildQueryString(opts)
	params := q.Query()
	for _, fixedIP := range opts.FixedIPs {
		params.Add("fixed_ips", fixedIP.String())
	}
	q = &url.URL{RawQuery: params.Encode()}
	return q.String(), err
}

// List returns a Pager which allows you to iterate over a collection of
// ports. It accepts a ListOpts struct, which allows you to filter and sort
// the returned collection for greater efficiency.
//
// Default policy settings return only those ports that are owned by the tenant
// who submits the request, unless the request is submitted by a user with
// administrative rights.
func List(c *gophercloud.ServiceClient, opts ListOptsBuilder) pagination.Pager {
	url := listURL(c)
	if opts != nil {
		query, err := opts.ToPortListQuery()
		if err != nil {
			return pagination.Pager{Err: err}
		}
		url += query
	}
	return pagination.NewPager(c, url, func(r pagination.PageResult) pagination.Page {
		return PortPage{pagination.LinkedPageBase{PageResult: r}}
	})
}

// Get retrieves a specific port based on its unique ID.
func Get(c *gophercloud.ServiceClient, id string) (r GetResult) {
	resp, err := c.Get(getURL(c, id), &r.Body, nil)
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}

// CreateOptsBuilder allows extensions to add additional parameters to the
// Create request.
type CreateOptsBuilder interface {
	ToPortCreateMap() (map[string]interface{}, error)
}

// CreateOpts represents the attributes used when creating a new port.
type CreateOpts struct {
	NetworkID           string             `json:"network_id" required:"true"`
	Name                string             `json:"name,omitempty"`
	Description         string             `json:"description,omitempty"`
	AdminStateUp        *bool              `json:"admin_state_up,omitempty"`
	MACAddress          string             `json:"mac_address,omitempty"`
	FixedIPs            interface{}        `json:"fixed_ips,omitempty"`
	DeviceID            string             `json:"device_id,omitempty"`
	DeviceOwner         string             `json:"device_owner,omitempty"`
	TenantID            string             `json:"tenant_id,omitempty"`
	ProjectID           string             `json:"project_id,omitempty"`
	SecurityGroups      *[]string          `json:"security_groups,omitempty"`
	AllowedAddressPairs []AddressPair      `json:"allowed_address_pairs,omitempty"`
	ValueSpecs          *map[string]string `json:"value_specs,omitempty"`
}

// ToPortCreateMap builds a request body from CreateOpts.
func (opts CreateOpts) ToPortCreateMap() (map[string]interface{}, error) {
	return gophercloud.BuildRequestBody(opts, "port")
}

// Create accepts a CreateOpts struct and creates a new network using the values
// provided. You must remember to provide a NetworkID value.
func Create(c *gophercloud.ServiceClient, opts CreateOptsBuilder) (r CreateResult) {
	b, err := opts.ToPortCreateMap()
	if err != nil {
		r.Err = err
		return
	}
	resp, err := c.Post(createURL(c), b, &r.Body, nil)
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}

// UpdateOptsBuilder allows extensions to add additional parameters to the
// Update request.
type UpdateOptsBuilder interface {
	ToPortUpdateMap() (map[string]interface{}, error)
}

// UpdateOpts represents the attributes used when updating an existing port.
type UpdateOpts struct {
	Name                *string            `json:"name,omitempty"`
	Description         *string            `json:"description,omitempty"`
	AdminStateUp        *bool              `json:"admin_state_up,omitempty"`
	FixedIPs            interface{}        `json:"fixed_ips,omitempty"`
	DeviceID            *string            `json:"device_id,omitempty"`
	DeviceOwner         *string            `json:"device_owner,omitempty"`
	SecurityGroups      *[]string          `json:"security_groups,omitempty"`
	AllowedAddressPairs *[]AddressPair     `json:"allowed_address_pairs,omitempty"`
	ValueSpecs          *map[string]string `json:"value_specs,omitempty"`

	// RevisionNumber implements extension:standard-attr-revisions. If != "" it
	// will set revision_number=%s. If the revision number does not match, the
	// update will fail.
	RevisionNumber *int `json:"-" h:"If-Match"`
}

// ToPortUpdateMap builds a request body from UpdateOpts.
func (opts UpdateOpts) ToPortUpdateMap() (map[string]interface{}, error) {
	return gophercloud.BuildRequestBody(opts, "port")
}

// Update accepts a UpdateOpts struct and updates an existing port using the
// values provided.
func Update(c *gophercloud.ServiceClient, id string, opts UpdateOptsBuilder) (r UpdateResult) {
	b, err := opts.ToPortUpdateMap()
	if err != nil {
		r.Err = err
		return
	}
	h, err := gophercloud.BuildHeaders(opts)
	if err != nil {
		r.Err = err
		return
	}
	for k := range h {
		if k == "If-Match" {
			h[k] = fmt.Sprintf("revision_number=%s", h[k])
		}
	}
	resp, err := c.Put(updateURL(c, id), b, &r.Body, &gophercloud.RequestOpts{
		MoreHeaders: h,
		OkCodes:     []int{200, 201},
	})
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}

// Delete accepts a unique ID and deletes the port associated with it.
func Delete(c *gophercloud.ServiceClient, id string) (r DeleteResult) {
	resp, err := c.Delete(deleteURL(c, id), nil)
	_, r.Header, r.Err = gophercloud.ParseResponse(resp, err)
	return
}
