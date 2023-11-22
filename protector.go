package epp

import (
	"fmt"
	"net/http"
)

type Protector interface {
	GetName() string
	GetType() string
	Validate(r *http.Request) (ProtectorInfo, error)
}

type ProtectorInfo interface {
	GetName() string
	GetType() string
}

type configProtector struct {
	Name   string                 `mapstructure:"name"`
	Type   string                 `mapstructure:"type"`
	Config map[string]interface{} `mapstructure:",remain"`
}

// InitializeEndpointProtection loads all supported endpoint protectors from config
func initProtectors(cfgProtectors []configProtector) (err error) {
	protectorIdMap = make(map[string]int)

	for _, protector := range cfgProtectors {
		var eppProtector Protector

		switch {
		case protector.Type == "basic":
			if eppProtector, err = NewBasicAuthProtector(protector.Name, protector.Config); err != nil {
				return err
			}
		case protector.Type == "apikey":
			if eppProtector, err = NewApiKeyProtector(protector.Name, protector.Config); err != nil {
				return err
			}
		case protector.Type == "ipaddress":
			if eppProtector, err = NewIPAddressProtector(protector.Name, protector.Config); err != nil {
				return err
			}
		case protector.Type == "bearer":
			if bearerKeyManager == nil {
				bearerKeyManager = NewBearerKeyManager()
			}
			if eppProtector, err = NewBearerProtector(protector.Name, protector.Config, bearerKeyManager); err != nil {
				return err
			}
		}
		//---------
		if eppProtector != nil {
			if _, ok := protectorIdMap[eppProtector.GetName()]; !ok {
				protectors = append(protectors, eppProtector)
				protectorIdMap[eppProtector.GetName()] = len(protectors) - 1
			} else {
				return fmt.Errorf("duplicated name in protector config. '%s'", eppProtector.GetName())
			}
		}
	}
	return nil
}
