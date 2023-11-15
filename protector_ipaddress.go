package epp

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
	"net"
	"net/http"
)

type IPAddressProtector struct {
	Name      string   `mapstructure:"name"`
	Type      string   `mapstructure:"type"`
	Addresses []string `mapstructure:"addresses"`
	addresses []*net.IPNet
}

type IPAddressProtectorInfo struct {
	protector      *IPAddressProtector
	ClientIP       net.IP
	MatchedAddress *net.IPNet
}

// NewIPAddressProtector initialize
func NewIPAddressProtector(name string, config map[string]interface{}) (protector *IPAddressProtector, err error) {
	if err = mapstructure.Decode(config, &protector); err != nil {
		return nil, err
	}
	protector.Name = name
	protector.Type = "ipaddress"

	for _, addr := range protector.Addresses {

		if _, netAddr, aErr := net.ParseCIDR(addr); aErr != nil {
			return nil, err
		} else {
			protector.addresses = append(protector.addresses, netAddr)
		}
	}

	return protector, err
}

// GetName returns protector name
func (p *IPAddressProtector) GetName() string {
	return p.Name
}

// GetType returns type
func (p *IPAddressProtector) GetType() string {
	return p.Type
}

func (p *IPAddressProtector) Validate(r *http.Request) (ProtectorInfo, error) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, err
	}
	clientIp := net.ParseIP(ip)
	if clientIp == nil {
		return nil, fmt.Errorf("clientIp is invalid")
	}

	for _, addr := range p.addresses {
		if addr.Contains(clientIp) {
			iapi := &IPAddressProtectorInfo{protector: p, ClientIP: clientIp, MatchedAddress: addr}
			return iapi, nil
		}
	}

	return nil, nil
}

func (i IPAddressProtectorInfo) GetName() string {
	return i.protector.GetName()
}

func (i IPAddressProtectorInfo) GetType() string {
	return i.protector.GetType()
}
