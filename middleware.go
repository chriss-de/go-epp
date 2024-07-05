package epp

import (
	"context"
	"fmt"
	"net/http"
	"os"
)

type contextKey struct {
	name string
}

var eppCtxKey = &contextKey{"endpointProtection"}

type Info struct {
	Infos []ProtectorInfo
	ACLs  map[string]struct{}
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eppInfo := &Info{ACLs: make(map[string]struct{})}

		for _, ep := range endpoints {
			if ep.regexPath.MatchString(r.URL.Path) {
				for _, protector := range ep.protectedBy {
					if info, err := protector.Validate(r); err == nil {
						if info != nil {
							eppInfo.Infos = append(eppInfo.Infos, info)
							for _, acl := range ep.aclList {
								eppInfo.ACLs[acl] = struct{}{}
							}
						}
					} else {
						logger.Error("middleware error", "error", err)
					}
				}
			}
		}

		if config.DebugLog {
			_, _ = fmt.Fprintf(os.Stdout, "EPP_DEBUG: protectors:[")
			for _, info := range eppInfo.Infos {
				_, _ = fmt.Fprintf(os.Stdout, "%+v", info)
			}
			_, _ = fmt.Fprintf(os.Stdout, "] ; ACLs: %+v \n", eppInfo.ACLs)
		}

		ctx := context.WithValue(r.Context(), eppCtxKey, eppInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// InfoFromContext restores epp info from ctx
func InfoFromContext(ctx context.Context) (i *Info, err error) {
	var ok bool

	if i, ok = ctx.Value(eppCtxKey).(*Info); !ok {
		err = fmt.Errorf("invalid endpoint protection in context")
	}

	return i, err
}
