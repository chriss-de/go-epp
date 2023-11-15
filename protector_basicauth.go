package epp

import (
	"encoding/base64"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"net/http"
	"strings"
)

type BasicAuthCredential struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Hashed   string `mapstructure:"hashed"`
	hasher   func(string) string
}

type BasicAuthProtectorInfo struct {
	protector *BasicAuthProtector
	Username  string
}

type BasicAuthProtector struct {
	Name          string                `mapstructure:"name"`
	Type          string                `mapstructure:"type"`
	Credentials   []BasicAuthCredential `mapstructure:"credentials"`
	credentialMap map[string]int
}

// NewBasicAuthProtector initialize
func NewBasicAuthProtector(name string, config map[string]interface{}) (protector *BasicAuthProtector, err error) {
	if err = mapstructure.Decode(config, &protector); err != nil {
		return nil, err
	}
	protector.Name = name
	protector.Type = "basic"
	protector.credentialMap = make(map[string]int)

	for credIdx, cred := range protector.Credentials {
		protector.credentialMap[cred.Username] = credIdx

		switch {
		case cred.Hashed == "sha256":
			protector.Credentials[credIdx].hasher = stringHashSha256
		case cred.Hashed == "sha1":
			protector.Credentials[credIdx].hasher = stringHashSha1
		case cred.Hashed == "md5":
			protector.Credentials[credIdx].hasher = stringHashMd5

		}
	}

	return protector, err
}

// GetName returns protector name
func (p *BasicAuthProtector) GetName() string {
	return p.Name
}

// GetType returns type
func (p *BasicAuthProtector) GetType() string {
	return p.Type
}

func (p *BasicAuthProtector) Validate(r *http.Request) (ProtectorInfo, error) {
	authHeaderValue := r.Header.Get("Authorization")
	if basicValue, found := strings.CutPrefix(authHeaderValue, "Basic "); found {
		// decode from base64
		decodedBasicValue, err := base64.StdEncoding.DecodeString(basicValue)
		if err != nil {
			return nil, err
		}
		creds := strings.Split(string(decodedBasicValue), ":")
		if len(creds) != 2 {
			return nil, fmt.Errorf("invalid basic auth value")
		}

		//
		username, password := creds[0], creds[1]
		if credIdx, found := p.credentialMap[username]; found {
			cred := p.Credentials[credIdx]

			if cred.hasher != nil {
				password = cred.hasher(password)
			}

			if password == cred.Password {
				bapi := &BasicAuthProtectorInfo{protector: p, Username: username}

				return bapi, nil
			}
			return nil, nil
		}
	}
	return nil, nil
}

func (b BasicAuthProtectorInfo) GetName() string {
	return b.protector.GetName()
}

func (b BasicAuthProtectorInfo) GetType() string {
	return b.protector.GetType()
}
