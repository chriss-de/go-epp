package epp

import (
	"context"
	"fmt"
	"net/http"
)

func HasACL(ctx context.Context, acl string) bool {
	epp, err := InfoFromContext(ctx)
	if err != nil {
		logger.Error(err)
	}
	if _, has := epp.ACLs[acl]; has {
		return true
	}

	return false
}

func NeedACL(acl string, func401 func(http.ResponseWriter, *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if HasACL(r.Context(), acl) {
				next.ServeHTTP(rw, r.WithContext(r.Context()))
			} else {
				func401(rw, r)
			}
		})
	}
}

func GetValueFromToken(ctx context.Context, key string) (any, error) {
	epp, err := InfoFromContext(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range epp.Infos {
		switch pbi := p.(type) {
		case *BearerProtectorInfo:
			return pbi.GetValueFromToken(key), nil
		}
	}

	return nil, fmt.Errorf("no token in request")
}

func GetStringFromToken(ctx context.Context, key string) (string, error) {
	epp, err := InfoFromContext(ctx)
	if err != nil {
		return "", err
	}
	for _, p := range epp.Infos {
		switch pbi := p.(type) {
		case *BearerProtectorInfo:
			return pbi.GetStringFromToken(key), nil
		}

	}

	return "", fmt.Errorf("no token in request")
}

//func GetStringsFromToken(ctx context.Context, key string) []string {
//
//}
