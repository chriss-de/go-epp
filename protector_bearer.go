package epp

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type bearerMetaData struct {
	JwksUri string `json:"jwks_uri"`
}

type BearerProtector struct {
	Name              string                 `mapstructure:"name"`
	Type              string                 `mapstructure:"type"`
	MetaUrl           string                 `mapstructure:"meta_url"`
	JwksUrl           string                 `mapstructure:"jwks_url"`
	ClaimValidation   map[string]interface{} `mapstructure:"claim_validation"`
	KeysFetchInterval time.Duration          `mapstructure:"keys_fetch_interval"`
	Keys              []bearerSignKey        `json:"keys"`
	keysMap           map[string]int
	keysAccessLck     sync.RWMutex
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
		Result:     protector,
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
		err         error
	)

	authHeaderValue := r.Header.Get("Authorization")
	if bearerValue, found := strings.CutPrefix(authHeaderValue, "Bearer "); found {
		if token, err = jwt.ParseWithClaims(bearerValue, &tokenClaims, bearerKeyManager.getSignatureKey); err != nil {
			return nil, err
		}
		if token == nil {
			return nil, fmt.Errorf("no token")
		}

		for claimName, claimValue := range p.ClaimValidation {
			if valueInToken, claimFound := tokenClaims[claimName]; claimFound {
				// TODO: compare of array OR value in arrays OR
				if valueInToken != claimValue {
					return nil, fmt.Errorf("invalid claim")
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
	v := b.getFromToken(key, b.TokenClaims)
	if vs, ok := v.(string); ok {
		return vs
	}
	return ""
}

func (b *BearerProtectorInfo) getFromToken(key string, t map[string]interface{}) interface{} {
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
			return b.getFromToken(newKey, t)
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
