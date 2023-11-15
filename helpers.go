package epp

import (
	"context"
	"net/http"
)

func HasACL(ctx context.Context, acl string) bool {
	epp, err := EppInfoFromContext(ctx)
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
