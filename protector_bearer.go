package epp

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type bearerMetaData struct {
	JwksUri string `json:"jwks_uri"`
}

type bearerSignKey struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5t string   `json:"x5t"`
	X5c []string `json:"x5c"`
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
func NewBearerProtector(name string, config map[string]interface{}) (protector *BearerProtector, err error) {
	if err = mapstructure.Decode(config, &protector); err != nil {
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
	if err = protector.fetchKeys(); err != nil {
		return nil, err
	}

	go func() {
		logger.Info("interval", protector.KeysFetchInterval.String(), "Starting background task to fetch keys from server")
		for {
			time.Sleep(protector.KeysFetchInterval)
			if err = protector.fetchKeys(); err != nil {
				logger.Error(err)
			}
		}
	}()

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
		if token, err = jwt.ParseWithClaims(bearerValue, &tokenClaims, p.getSignatureKey); err != nil {
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

// fetchKeys fetches keys from JwksURI
func (p *BearerProtector) fetchKeys() (err error) {
	var (
		httpClient = &http.Client{Timeout: time.Second * 15}
		request    *http.Request
		response   *http.Response
	)

	logger.Info("oauth", p.Name, "url", p.JwksUrl, "timeout", httpClient.Timeout.String(), "Fetching new keys from server")

	if request, err = http.NewRequest("GET", p.JwksUrl, nil); err != nil {
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

	if err = json.NewDecoder(response.Body).Decode(&p); err != nil {
		return err
	}

	// create map
	p.keysAccessLck.Lock()
	p.keysMap = make(map[string]int)
	for keyIdx, key := range p.Keys {
		p.keysMap[key.Kid] = keyIdx
	}
	p.keysAccessLck.Unlock()

	return nil
}

// getSignatureKey returns public key to validate token signature
func (p *BearerProtector) getSignatureKey(token *jwt.Token) (out interface{}, err error) {
	var (
		ok        bool
		keyIdx    int
		kid       string
		x5t       string
		publicKey crypto.PublicKey
		key       bearerSignKey
	)

	if kid, ok = token.Header["kid"].(string); !ok {
		return nil, fmt.Errorf("could not find 'kid' in token header")
	}

	p.keysAccessLck.RLock()
	if keyIdx, ok = p.keysMap[kid]; !ok {
		return nil, fmt.Errorf("could not find kid '%s' in local key cache. keys in cache: %d", kid, len(p.keysMap))
	}
	key = p.Keys[keyIdx]
	p.keysAccessLck.RUnlock()

	if x5t, ok = token.Header["x5t"].(string); ok {
		if key.X5t != x5t {
			return nil, fmt.Errorf("key mismatch at value 'x5t'")
		}
	}

	publicKey = getPublicKeyFromModulusAndExponent(key.N, key.E)

	return publicKey, nil

}

// getPublicKeyFromModulusAndExponent gets public key from Modules and Exponent provided from JwksURI
func getPublicKeyFromModulusAndExponent(n, e string) *rsa.PublicKey {
	nBytes, _ := base64.RawURLEncoding.DecodeString(n)
	eBytes, _ := base64.RawURLEncoding.DecodeString(e)
	z := new(big.Int)
	z.SetBytes(nBytes)
	//decoding key.E returns a three byte slice, https://golang.org/pkg/encoding/binary/#Read and other conversions fail
	//since they are expecting to read as many bytes as the size of int being returned (4 bytes for uint32 for example)
	var buffer bytes.Buffer
	buffer.WriteByte(0)
	buffer.Write(eBytes)
	exponent := binary.BigEndian.Uint32(buffer.Bytes())
	return &rsa.PublicKey{N: z, E: int(exponent)}
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
