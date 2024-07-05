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
	Kty       string   `json:"kty"`
	Use       string   `json:"use"`
	Kid       string   `json:"kid"`
	N         string   `json:"n"`
	E         string   `json:"e"`
	X5t       string   `json:"x5t"`
	X5c       []string `json:"x5c"`
	publicKey *rsa.PublicKey
}

type JwksUrlResponse struct {
	Keys []bearerSignKey `json:"keys"`
}

type KeyFetch struct {
	Name     string
	KeyUrl   string
	Interval time.Duration
	keys     []*bearerSignKey
}

type BearerKeyManager struct {
	tokenKeysMap  map[string]*bearerSignKey // map with 'kid' to idx in keys for bearerSignKey
	tokenIdpMap   map[string]string
	tokenMapsLck  sync.RWMutex
	keyFetches    map[string]*KeyFetch
	keyFetchesLck sync.Mutex
}

var idOrder = []string{"kid", "x5t"}

func NewBearerKeyManager() *BearerKeyManager {
	return &BearerKeyManager{
		tokenKeysMap: make(map[string]*bearerSignKey),
		tokenIdpMap:  make(map[string]string),
		keyFetches:   make(map[string]*KeyFetch),
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

	var newKeys *JwksUrlResponse
	if err = json.NewDecoder(response.Body).Decode(&newKeys); err != nil {
		return err
	}

	// create map
	bkm.tokenMapsLck.Lock()
	for _, oldKey := range keyFetch.keys {
		delete(bkm.tokenKeysMap, oldKey.getID())
	}

	keyFetch.keys = make([]*bearerSignKey, len(newKeys.Keys))
	for idx, key := range newKeys.Keys {
		_key := key
		_key.publicKey = getPublicKeyFromModulusAndExponent(_key.N, _key.E)
		bkm.tokenKeysMap[_key.getID()] = &_key
		bkm.tokenIdpMap[_key.getID()] = keyFetch.Name
		keyFetch.keys[idx] = &_key
	}
	bkm.tokenMapsLck.Unlock()

	// queue fetch after interval - time.AfterFunc(k.Interval)
	bkm.queueNewFetch(keyFetch)

	return nil
}

func (bkm *BearerKeyManager) queueNewFetch(k *KeyFetch) {
	logger.Info("Queuing new fetch", "interval", k.Interval.String())
	go func() {
		time.AfterFunc(k.Interval, func() {
			if err := bkm.fetchKeys(k.Name); err != nil {
				logger.Error("fetch queue", "error", err)
			}
		})
	}()
}

func (bkm *BearerKeyManager) getBearerForToken(id string) (string, bool) {
	bkm.tokenMapsLck.RLock()
	defer bkm.tokenMapsLck.RUnlock()
	k, o := bkm.tokenIdpMap[id]
	return k, o
}

func (bkm *BearerKeyManager) getTokenId(tokenHeader map[string]interface{}) (tokenId string, err error) {
	var (
		iTokenId interface{}
		found    bool
		castOk   bool
	)

	for _, idVal := range idOrder {
		if iTokenId, found = tokenHeader[idVal]; found {
			break
		}
	}
	if !found {
		return "", fmt.Errorf("no valid token id found in header")
	}

	if tokenId, castOk = iTokenId.(string); !castOk {
		return "", fmt.Errorf("could not parse '%v' to string as token id", iTokenId)
	}

	return tokenId, nil
}

// getSignatureKey returns public key to validate token signature
func (bkm *BearerKeyManager) getSignatureKey(token *jwt.Token) (out interface{}, err error) {
	var (
		ok        bool
		tokenId   string
		publicKey crypto.PublicKey
		key       *bearerSignKey
	)

	if tokenId, err = bkm.getTokenId(token.Header); err != nil {
		return nil, fmt.Errorf("could not find valid token id in token header. %s", err)
	}

	bkm.tokenMapsLck.RLock()
	if key, ok = bkm.tokenKeysMap[tokenId]; !ok {
		return nil, fmt.Errorf("could not find tokenId '%s' in local key cache. keys in cache: %d", tokenId, len(bkm.tokenKeysMap))
	}
	bkm.tokenMapsLck.RUnlock()

	publicKey = key.publicKey
	if publicKey == nil {
		publicKey = getPublicKeyFromModulusAndExponent(key.N, key.E)
	}

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

func (bsk *bearerSignKey) getID() string {
	for _, idVal := range idOrder {
		switch {
		case idVal == "kid":
			return bsk.Kid

		}
	}
	return bsk.X5t
}
