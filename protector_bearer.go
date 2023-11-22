package epp

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"io"
	"net/http"
	"strings"
	"time"
)

type bearerMetaData struct {
	JwksUri string `json:"jwks_uri"`
}

type ClaimValidation struct {
	Key      string `mapstructure:"key"`
	Type     string `mapstructure:"type"`
	Value    string `mapstructure:"value"`
	Length   int    `mapstructure:"length"`
	Contains string `mapstructure:"contains"`
}

type BearerProtector struct {
	Name              string            `mapstructure:"name"`
	Type              string            `mapstructure:"type"`
	MetaUrl           string            `mapstructure:"meta_url"`
	JwksUrl           string            `mapstructure:"jwks_url"`
	KeysFetchInterval time.Duration     `mapstructure:"keys_fetch_interval"`
	ClaimsValidations []ClaimValidation `mapstructure:"claims_validations"`
}

type BearerProtectorInfo struct {
	protector   *BearerProtector
	TokenClaims jwt.MapClaims
	Token       *jwt.Token
}

// NewBearerProtector initialize
func NewBearerProtector(name string, config map[string]interface{}, bkm *BearerKeyManager) (protector *BearerProtector, err error) {
	var decoder *mapstructure.Decoder
	decoder, err = mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
		Result:     &protector,
	})

	if err = decoder.Decode(config); err != nil {
		return nil, err
	}
	protector.Name = name
	protector.Type = "bearer"

	// sanity check
	if protector.MetaUrl == "" && protector.JwksUrl == "" {
		return nil, fmt.Errorf("need meta_url OR jwks_url")
	}
	if protector.MetaUrl != "" && protector.JwksUrl != "" {
		logger.Warning("prefer meta_url over jwks_url")
	}

	if protector.MetaUrl != "" {
		if err = protector.fetchMetaData(); err != nil {
			return nil, err
		}
	}

	//
	if protector.KeysFetchInterval == 0 {
		protector.KeysFetchInterval = 1 * time.Hour
	}

	keyFetch := &KeyFetch{Name: protector.Name, KeyUrl: protector.JwksUrl, Interval: protector.KeysFetchInterval}
	if err = bkm.AddKeyFetch(keyFetch); err != nil {
		return nil, err
	}

	return protector, err
}

// GetName returns protector name
func (p *BearerProtector) GetName() string {
	return p.Name
}

// GetType returns type
func (p *BearerProtector) GetType() string {
	return p.Type
}

func (p *BearerProtector) Validate(r *http.Request) (ProtectorInfo, error) {
	var (
		token       *jwt.Token
		tokenClaims = make(jwt.MapClaims)
		typeOk      bool
		kid         string
		err         error
	)

	authHeaderValue := r.Header.Get("Authorization")
	if bearerValue, found := strings.CutPrefix(authHeaderValue, "Bearer "); found {
		token, err = jwt.ParseWithClaims(bearerValue, &tokenClaims, bearerKeyManager.getSignatureKey)
		if token == nil {
			return nil, fmt.Errorf("no token")
		}
		if kid, typeOk = token.Header["kid"].(string); !typeOk {
			return nil, fmt.Errorf("could not find 'kid' in token header")
		}
		if bearer, found := bearerKeyManager.getBearerForKid(kid); !found || bearer != p.Name {
			// token is not for this BearerProtector - silently drop
			return nil, nil
		}
		if err != nil {
			return nil, err
		}

		for _, cv := range p.ClaimsValidations {
			v := getFromToken(cv.Key, tokenClaims)
			switch typedValue := v.(type) {
			case string:
				if typedValue != cv.Value {
					return nil, fmt.Errorf("invalid claim for '%s'", cv.Value)
				}
			}
		}

		bpi := &BearerProtectorInfo{protector: p, TokenClaims: tokenClaims, Token: token}
		return bpi, nil

	}
	return nil, nil
}

// fetchMetaData fetches all values for IDP from metadata url
func (p *BearerProtector) fetchMetaData() (err error) {
	var (
		httpClient = &http.Client{}
		request    *http.Request
		response   *http.Response
		metaData   bearerMetaData
	)

	if request, err = http.NewRequest("GET", p.MetaUrl, nil); err != nil {
		return err
	}
	if response, err = httpClient.Do(request); err != nil {
		return err
	}
	if response.Body != nil {
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(response.Body)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf(response.Status)
	}

	err = json.NewDecoder(response.Body).Decode(&metaData)
	if err != nil {
		return err
	}

	p.JwksUrl = metaData.JwksUri

	return nil
}

func (b *BearerProtectorInfo) GetStringFromToken(key string) string {
	v := getFromToken(key, b.TokenClaims)
	if vs, ok := v.(string); ok {
		return vs
	}
	return ""
}

func getFromToken(key string, t map[string]interface{}) interface{} {
	keySplitted := strings.Split(key, ".")
	for _, keyPart := range keySplitted {
		v, exists := t[keyPart]
		switch {
		case exists && len(keySplitted) == 1:
			return v
		case !exists:
			return nil
		default:
			newKey, _ := strings.CutPrefix(key, keyPart+".")
			return getFromToken(newKey, t)
		}
	}
	return nil
}

func (b *BearerProtectorInfo) GetName() string {
	return b.protector.GetName()
}

func (b *BearerProtectorInfo) GetType() string {
	return b.protector.GetType()
}
