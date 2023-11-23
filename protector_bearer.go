package epp

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

type bearerMetaData struct {
	JwksUri string `json:"jwks_uri"`
}

type ClaimValidation struct {
	Key      string  `mapstructure:"key"`
	Type     *string `mapstructure:"type"`
	Value    any     `mapstructure:"value"`
	Length   *int    `mapstructure:"length"`
	Contains any     `mapstructure:"contains"`
	//GreaterThan *int    `mapstructure:"gt"`
	//LessThan    *int    `mapstructure:"lt"`
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
		logger.Info("prefer meta_url over jwks_url")
	}

	// validation sanity check
	for _, cv := range protector.ClaimsValidations {
		if cv.Key == "" {
			return nil, fmt.Errorf("claim validation needs a key")
		}
		if cv.Value == nil && cv.Type == nil && cv.Contains == nil && cv.Length == nil {
			return nil, fmt.Errorf("need at least one validation check")
		}
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
			if v != nil {
				switch typedValue := v.(type) {
				case string:
					if cv.Value != nil && typedValue != cv.Value {
						return nil, errorMessage(cv.Key, "value")
					}
					if cv.Length != nil && len(typedValue) != *cv.Length {
						return nil, errorMessage(cv.Key, "length")
					}
					if cv.Type != nil && *cv.Type != "string" {
						return nil, errorMessage(cv.Key, "type")
					}
					if cv.Contains != nil && strings.Contains(typedValue, fmt.Sprint(cv.Contains)) {
						return nil, errorMessage(cv.Key, "contains")
					}
				case int, int8, int16, int32, int64, float32, float64:
					if cv.Value != nil && typedValue != cv.Value {
						return nil, errorMessage(cv.Key, "value")
					}
					if cv.Type != nil && *cv.Type != "number" {
						return nil, errorMessage(cv.Key, "type")
					}
					//if cv.GreaterThan != nil && typedValue.(float64) <= (*cv.GreaterThan).(float64) {
					//	return nil, errorMessage(cv.Key, "gt")
					//}
					//if cv.LessThan != nil && typedValue >= *cv.LessThan {
					//	return nil, errorMessage(cv.Key, "lt")
					//}
				case []interface{}:
					if cv.Length != nil && len(typedValue) != *cv.Length {
						return nil, errorMessage(cv.Key, "length")
					}
					if cv.Type != nil && *cv.Type != "array" {
						return nil, errorMessage(cv.Key, "type")
					}
					if cv.Contains != nil && !slices.Contains(typedValue, cv.Contains) {
						return nil, errorMessage(cv.Key, "contains")
					}
				}
			} else {
				return nil, errorMessage(cv.Key, "not found")
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

func (b *BearerProtectorInfo) GetValueFromToken(key string) any {
	return getFromToken(key, b.TokenClaims)
}

func getFromToken(key string, t map[string]interface{}) interface{} {
	sKey := strings.Split(key, ".")
	for _, keyPart := range sKey {
		v, exists := t[keyPart]
		switch {
		case exists && len(sKey) == 1:
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

func errorMessage(key string, msg string) error {
	return fmt.Errorf("invalid claim for '%s' - %s", key, msg)
}

func (b *BearerProtectorInfo) GetName() string {
	return b.protector.GetName()
}

func (b *BearerProtectorInfo) GetType() string {
	return b.protector.GetType()
}
