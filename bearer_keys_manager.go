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
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type bearerSignKey struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5t string   `json:"x5t"`
	X5c []string `json:"x5c"`
}

type KeyFetch struct {
	Name     string
	KeyUrl   string
	Interval time.Duration
	keys     []bearerSignKey
}

type BearerKeyManager struct {
	keysMap       map[string]*bearerSignKey // map with 'kid' to idx in keys for bearerSignKey
	keysMapLck    sync.RWMutex
	keyFetches    map[string]*KeyFetch
	keyFetchesLck sync.Mutex
}

func NewBearerKeyManager() *BearerKeyManager {
	return &BearerKeyManager{
		keysMap:    make(map[string]*bearerSignKey),
		keyFetches: make(map[string]*KeyFetch),
	}
}

func (bkm *BearerKeyManager) AddKeyFetch(k *KeyFetch) error {
	bkm.keyFetchesLck.Lock()
	bkm.keyFetches[k.Name] = k
	bkm.keyFetchesLck.Unlock()

	// fetch direct and return err
	if err := bkm.fetchKeys(k.Name); err != nil {
		return err
	}

	// queue fetch after interval - time.AfterFunc(k.Interval)
	time.AfterFunc(k.Interval, func() {
		if err := bkm.fetchKeys(k.Name); err != nil {
			logger.Error(err)
		}
	})

	return nil
}

// fetchKeys fetches keys from JwksURI
func (bkm *BearerKeyManager) fetchKeys(name string) (err error) {
	var (
		httpClient = &http.Client{Timeout: time.Second * 15}
		request    *http.Request
		response   *http.Response
		keyFetch   *KeyFetch
		found      bool
	)
	bkm.keyFetchesLck.Lock()
	defer bkm.keyFetchesLck.Unlock()

	if keyFetch, found = bkm.keyFetches[name]; !found {
		return fmt.Errorf("could not find keyFetch for %s", name)
	}

	logger.Info("oauth", keyFetch.Name, "url", keyFetch.KeyUrl, "timeout", httpClient.Timeout.String(), "Fetching new keys from server")

	if request, err = http.NewRequest("GET", keyFetch.KeyUrl, nil); err != nil {
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

	var newKeys = make([]bearerSignKey, 0)
	if err = json.NewDecoder(response.Body).Decode(&newKeys); err != nil {
		return err
	}

	// create map
	bkm.keysMapLck.Lock()
	for _, oldKey := range keyFetch.keys {
		delete(bkm.keysMap, oldKey.Kid)
	}

	keyFetch.keys = newKeys
	for _, key := range keyFetch.keys {
		bkm.keysMap[key.Kid] = &key
	}
	bkm.keysMapLck.Unlock()

	// queue fetch after interval - time.AfterFunc(k.Interval)
	time.AfterFunc(keyFetch.Interval, func() {
		logger.Info("interval", keyFetch.Interval, "Queue new fetch")
		if err = bkm.fetchKeys(keyFetch.Name); err != nil {
			logger.Error(err)
		}
	})

	return nil
}

// getSignatureKey returns public key to validate token signature
func (bkm *BearerKeyManager) getSignatureKey(token *jwt.Token) (out interface{}, err error) {
	var (
		ok        bool
		kid       string
		x5t       string
		publicKey crypto.PublicKey
		key       *bearerSignKey
	)

	if kid, ok = token.Header["kid"].(string); !ok {
		return nil, fmt.Errorf("could not find 'kid' in token header")
	}

	bkm.keysMapLck.RLock()
	if key, ok = bkm.keysMap[kid]; !ok {
		return nil, fmt.Errorf("could not find kid '%s' in local key cache. keys in cache: %d", kid, len(bkm.keysMap))
	}
	bkm.keysMapLck.RUnlock()

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
