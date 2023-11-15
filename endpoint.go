package epp

import (
	"fmt"
	"regexp"
	"strings"
)

type Required string // any, all, none
const (
	RequireANY  Required = "any"
	RequireNONE Required = "none"
	RequireALL  Required = "all"
)

type configEndpoint struct {
	Path        string   `mapstructure:"path"`
	PathIsRegex bool     `mapstructure:"path_is_regex"`
	ProtectedBy []string `mapstructure:"protected_by"`
	Require     string   `mapstructure:"required"`
	ACLs        []string `mapstructure:"acls"`
}

type Endpoint struct {
	path        string
	regexPath   *regexp.Regexp
	required    Required
	protectedBy []Protector
	aclList     []string
}

// InitializeEndpointProtection loads all supported endpoint protectors from config
func initEndpoints(cfgEndpoints []configEndpoint) (err error) {
	//endpointIdMap = make(map[string]int)

	for _, endpoint := range cfgEndpoints {
		eppEndpoint := &Endpoint{
			path:    endpoint.Path,
			aclList: endpoint.ACLs,
		}

		if eppEndpoint.required, err = newRequiredFromString(endpoint.Require); err != nil {
			return err
		}

		if endpoint.PathIsRegex {
			eppEndpoint.regexPath = regexp.MustCompile(endpoint.Path)
		} else {
			eppEndpoint.regexPath = regexp.MustCompile(regexp.QuoteMeta(endpoint.Path))
		}

		for _, pb := range endpoint.ProtectedBy {
			if idx, ok := protectorIdMap[pb]; ok {
				eppEndpoint.protectedBy = append(eppEndpoint.protectedBy, protectors[idx])
			} else {
				return fmt.Errorf("unknown protector referenced")
			}
		}

		////---------
		//if _, ok := endpointIdMap[eppEndpoint.path]; !ok {
		endpoints = append(endpoints, eppEndpoint)
		//	endpointIdMap[eppEndpoint.path] = len(endpoints) - 1
		//}

	}
	return nil
}

func newRequiredFromString(req string) (Required, error) {
	if req == "" {
		return RequireALL, nil
	}
	switch {
	case strings.EqualFold(req, string(RequireANY)):
		return RequireANY, nil
	case strings.EqualFold(req, string(RequireNONE)):
		return RequireNONE, nil
	case strings.EqualFold(req, string(RequireALL)):
		return RequireALL, nil
	default:
		return "", fmt.Errorf("invalid require type")
	}
}
