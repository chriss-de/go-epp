package epp

import (
	"github.com/mitchellh/mapstructure"
	"net/http"
)

type ApiKeyKey struct {
	Name         string   `mapstructure:"name"`
	Value        string   `mapstructure:"value"`
	Hashed       string   `mapstructure:"hashed"`
	PopulateKeys []string `mapstructure:"populate_keys"`
	hasher       func(string) string
}

type ApiKeyProtectorInfo struct {
	protector        *ApiKeyProtector
	ApiKeyValue      string
	PopulatedHeaders map[string]string
}

type ApiKeyProtector struct {
	Name    string      `mapstructure:"name"`
	Type    string      `mapstructure:"type"`
	Keys    []ApiKeyKey `mapstructure:"keys"`
	keysMap map[string]int
}

// NewApiKeyProtector initialize
func NewApiKeyProtector(name string, config map[string]interface{}) (protector *ApiKeyProtector, err error) {
	if err = mapstructure.Decode(config, &protector); err != nil {
		return nil, err
	}
	protector.Name = name
	protector.Type = "apikey"
	protector.keysMap = make(map[string]int)

	for keyIdx, key := range protector.Keys {
		protector.keysMap[key.Name] = keyIdx

		switch {
		case key.Hashed == "sha256":
			protector.Keys[keyIdx].hasher = stringHashSha256
		case key.Hashed == "sha1":
			protector.Keys[keyIdx].hasher = stringHashSha1
		case key.Hashed == "md5":
			protector.Keys[keyIdx].hasher = stringHashMd5

		}
	}

	return protector, err
}

// GetName returns protector name
func (p *ApiKeyProtector) GetName() string {
	return p.Name
}

// GetType returns type
func (p *ApiKeyProtector) GetType() string {
	return p.Type
}

func (p *ApiKeyProtector) Validate(r *http.Request) (ProtectorInfo, error) {
	for apiKeyName, apiKeyIdx := range p.keysMap {
		apiKeyValue := r.Header.Get(apiKeyName)
		if apiKeyValue != "" {
			apiKey := p.Keys[apiKeyIdx]

			if apiKey.hasher != nil {
				apiKeyValue = apiKey.hasher(apiKeyValue)
			}

			if apiKeyValue == apiKey.Value {
				akpi := &ApiKeyProtectorInfo{protector: p, PopulatedHeaders: make(map[string]string), ApiKeyValue: apiKeyValue}
				for _, pKey := range apiKey.PopulateKeys {
					akpi.PopulatedHeaders[pKey] = r.Header.Get(pKey)
				}

				return akpi, nil
			}
		}
	}

	return nil, nil
}

func (i *ApiKeyProtectorInfo) GetName() string {
	return i.protector.GetName()
}

func (i *ApiKeyProtectorInfo) GetType() string {
	return i.protector.GetType()
}
