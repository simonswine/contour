package authentication

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	_type "github.com/envoyproxy/go-control-plane/envoy/type"
	rpc "github.com/gogo/googleapis/google/rpc"
	"github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
	//contourv1beta1 "github.com/heptio/contour/apis/contour/v1beta1"
)

var _ Authenticator = &Basic{}

// Basic implements a HTTP Basic Auth
type Basic struct {
	htpasswd *htpasswd.File
	realm    string
}

// NewBasic create a new basic auth instance
func NewBasic(realm string, htpasswdData []byte) (*Basic, error) {
	htpasswdFile, err := htpasswd.NewFromReader(
		bytes.NewReader(htpasswdData),
		htpasswd.DefaultSystems,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("error parsing htpasswd: %s", err)
	}

	return &Basic{
		realm:    realm,
		htpasswd: htpasswdFile,
	}, nil
}

func (b *Basic) responseAuthRequired() *envoy_auth_v2.CheckResponse {
	return &envoy_auth_v2.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.UNAUTHENTICATED),
		},
		HttpResponse: &envoy_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth_v2.DeniedHttpResponse{
				Body: "Not authorized",
				Status: &_type.HttpStatus{
					Code: _type.StatusCode_Unauthorized,
				},
				Headers: []*core.HeaderValueOption{
					&core.HeaderValueOption{
						Header: &core.HeaderValue{
							Key:   "WWW-Authenticate",
							Value: fmt.Sprintf(`Basic realm="%s"`, b.realm),
						},
					},
				},
			},
		},
	}
}

// Check implements the authentication check for Basic Auth
func (b *Basic) Check(log *logrus.Entry, ctx context.Context, req *envoy_auth_v2.CheckRequest) (*envoy_auth_v2.CheckResponse, error) {
	log = log.WithField("auth", "basic")
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	if headers == nil {
		log.Warn("headers no provided")
		return b.responseAuthRequired(), nil
	}

	authHeader, ok := headers["authorization"]
	if !ok {
		return b.responseAuthRequired(), nil
	}

	s := strings.SplitN(authHeader, " ", 2)
	if len(s) != 2 {
		log.Warn("unexpected amount of header fields")
		return b.responseAuthRequired(), nil
	}

	if s[0] != "Basic" {
		log.Warn("unexpected header")
		return b.responseAuthRequired(), nil
	}

	decoded, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		log.Warn("error decoding basic auth header: ", err)
		return b.responseAuthRequired(), nil
	}

	pair := strings.SplitN(string(decoded), ":", 2)
	if len(pair) != 2 {
		return b.responseAuthRequired(), nil
	}

	if !b.htpasswd.Match(pair[0], pair[1]) {
		return b.responseAuthRequired(), nil
	}

	// authenticated user

	// TODO: Expose username as header, remove authorization header
	return checkResponseOK(log), nil
}
