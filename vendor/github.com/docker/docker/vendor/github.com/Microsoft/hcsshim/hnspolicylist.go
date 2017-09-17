package hcsshim

import (
	"encoding/json"

	"github.com/sirupsen/logrus"
)

type RoutePolicy struct {
	Policy
	DestinationPrefix string `json:"DestinationPrefix,omitempty"`
	NextHop           string `json:"NextHop,omitempty"`
	EncapEnabled      bool   `json:"NeedEncap,omitempty"`
}

type ELBPolicy struct {
	LBPolicy
	SourceVIP string   `json:"SourceVIP,omitempty"`
	VIPs      []string `json:"VIPs,omitempty"`
	ILB       bool     `json:"ILB,omitempty"`
}

type LBPolicy struct {
	Policy
	Protocol     uint16 `json:"Protocol,omitempty"`
	InternalPort uint16
	ExternalPort uint16
}

type PolicyList struct {
	Id                 string   `json:"ID,omitempty"`
	EndpointReferences []string `json:"References,omitempty"`
	Policies           []string `json:"Policies,omitempty"`
}

// HNSPolicyListRequest makes a call into HNS to update/query a single network
func HNSPolicyListRequest(method, path, request string) (*PolicyList, error) {
	var policy PolicyList
	err := hnsCall(method, "/policylists/"+path, request, &policy)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

func HNSListPolicyListRequest() ([]PolicyList, error) {
	var plist []PolicyList
	err := hnsCall("GET", "/policylists/", "", &plist)
	if err != nil {
		return nil, err
	}

	return plist, nil
}

// PolicyListRequest makes a HNS call to modify/query a network endpoint
func PolicyListRequest(method, path, request string) (*PolicyList, error) {
	policylist := &PolicyList{}
	err := hnsCall(method, "/policylists/"+path, request, &policylist)
	if err != nil {
		return nil, err
	}

	return policylist, nil
}

// Create PolicyList by sending PolicyListRequest to HNS.
func (policylist *PolicyList) Create() (*PolicyList, error) {
	operation := "Create"
	title := "HCSShim::PolicyList::" + operation
	logrus.Debugf(title+" id=%s", policylist.Id)
	jsonString, err := json.Marshal(policylist)
	if err != nil {
		return nil, err
	}
	return PolicyListRequest("POST", "", string(jsonString))
}

// Create PolicyList by sending PolicyListRequest to HNS
func (policylist *PolicyList) Delete() (*PolicyList, error) {
	operation := "Delete"
	title := "HCSShim::PolicyList::" + operation
	logrus.Debugf(title+" id=%s", policylist.Id)

	return PolicyListRequest("DELETE", policylist.Id, "")
}

// Add an endpoint to a Policy List
func (policylist *PolicyList) AddEndpoint(endpoint *HNSEndpoint) (*PolicyList, error) {
	operation := "AddEndpoint"
	title := "HCSShim::PolicyList::" + operation
	logrus.Debugf(title+" id=%s, endpointId:%s", policylist.Id, endpoint.Id)

	_, err := policylist.Delete()
	if err != nil {
		return nil, err
	}

	// Add Endpoint to the Existing List
	policylist.EndpointReferences = append(policylist.EndpointReferences, "/endpoints/"+endpoint.Id)

	return policylist.Create()
}

// Remove an endpoint from the Policy List
func (policylist *PolicyList) RemoveEndpoint(endpoint *HNSEndpoint) (*PolicyList, error) {
	operation := "RemoveEndpoint"
	title := "HCSShim::PolicyList::" + operation
	logrus.Debugf(title+" id=%s, endpointId:%s", policylist.Id, endpoint.Id)

	_, err := policylist.Delete()
	if err != nil {
		return nil, err
	}

	elementToRemove := "/endpoints/" + endpoint.Id

	var references []string

	for _, endpointReference := range policylist.EndpointReferences {
		if endpointReference == elementToRemove {
			continue
		}
		references = append(references, endpointReference)
	}
	policylist.EndpointReferences = references
	return policylist.Create()
}

// AddLoadBalancer policy list for the specified endpoints
func AddLoadBalancer(endpoints []HNSEndpoint, isILB bool, vip string, protocol uint16, internalPort uint16, externalPort uint16) (*PolicyList, error) {
	operation := "AddLoadBalancer"
	title := "HCSShim::PolicyList::" + operation
	logrus.Debugf(title+" Vip:%s", vip)

	policylist := &PolicyList{}

	elbPolicy := &ELBPolicy{
		VIPs: []string{vip},
		ILB:  isILB,
	}
	elbPolicy.Type = ExternalLoadBalancer
	elbPolicy.Protocol = protocol
	elbPolicy.InternalPort = internalPort
	elbPolicy.ExternalPort = externalPort

	for _, endpoint := range endpoints {
		policylist.EndpointReferences = append(policylist.EndpointReferences, "/endpoints/"+endpoint.Id)
	}

	jsonString, err := json.Marshal(elbPolicy)
	if err != nil {
		return nil, err
	}

	policylist.Policies[0] = string(jsonString)
	return policylist.Create()
}

// AddLoadBalancer policy list for the specified endpoints
func AddRoute(endpoints []HNSEndpoint, destinationPrefix string, nextHop string, encapEnabled bool) (*PolicyList, error) {
	operation := "AddRoute"
	title := "HCSShim::PolicyList::" + operation
	logrus.Debugf(title+" destinationPrefix:%s", destinationPrefix)

	policylist := &PolicyList{}

	rPolicy := &RoutePolicy{
		DestinationPrefix: destinationPrefix,
		NextHop:           nextHop,
		EncapEnabled:      encapEnabled,
	}
	rPolicy.Type = Route

	for _, endpoint := range endpoints {
		policylist.EndpointReferences = append(policylist.EndpointReferences, "/endpoints/"+endpoint.Id)
	}

	jsonString, err := json.Marshal(rPolicy)
	if err != nil {
		return nil, err
	}

	policylist.Policies[0] = string(jsonString)
	return policylist.Create()
}
