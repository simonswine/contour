// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package authentication provides a gRPC implementation of the Envoy v2 External Auth API.
package authentication

import (
	"context"
	"fmt"
	"net/url"

	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	_type "github.com/envoyproxy/go-control-plane/envoy/type"
	rpc "github.com/gogo/googleapis/google/rpc"
	"github.com/sirupsen/logrus"
)

const (
	ContextName      = "authentication_name"
	ContextNamespace = "authentication_namespace"
)

type AuthenticationCache interface {
	LookUp(namespace, name string) (Authenticator, bool)
}

type Authenticator interface {
	Check(log *logrus.Entry, ctx context.Context, req *envoy_auth_v2.CheckRequest) (*envoy_auth_v2.CheckResponse, error)
}

type Handler struct {
	logrus.FieldLogger
	AuthenticationCache
}

func (h *Handler) Check(ctx context.Context, req *envoy_auth_v2.CheckRequest) (*envoy_auth_v2.CheckResponse, error) {
	// retrieve namespace / name from context
	namespace := req.GetAttributes().GetContextExtensions()[ContextNamespace]
	name := req.GetAttributes().GetContextExtensions()[ContextName]

	// prepare logger
	log := h.
		WithField(ContextName, name).
		WithField(ContextNamespace, namespace)

	auth, ok := h.AuthenticationCache.LookUp(namespace, name)
	if !ok {
		return checkResponseError(log, fmt.Errorf("unknown auth backend %s/%s", namespace, name)), nil
	}

	return auth.Check(log, ctx, req)
}

func checkResponseOK(log *logrus.Entry) *envoy_auth_v2.CheckResponse {
	log.Debug("request allowed")
	return &envoy_auth_v2.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.OK),
		},
		HttpResponse: &envoy_auth_v2.CheckResponse_OkResponse{
			OkResponse: &envoy_auth_v2.OkHttpResponse{},
		},
	}
}

func checkResponseRedirect(log *logrus.Entry, redirectURL *url.URL) *envoy_auth_v2.CheckResponse {
	log.Debugf("request redirected to '%s'", redirectURL.String())
	return &envoy_auth_v2.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.UNAUTHENTICATED),
		},
		HttpResponse: &envoy_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth_v2.DeniedHttpResponse{
				Headers: []*core.HeaderValueOption{
					&core.HeaderValueOption{
						Header: &core.HeaderValue{
							Key:   "Location",
							Value: redirectURL.String(),
						},
					},
				},
				Status: &_type.HttpStatus{
					Code: _type.StatusCode_Found,
				},
			},
		},
	}
}

func checkResponseError(log *logrus.Entry, err error) *envoy_auth_v2.CheckResponse {
	log.Warn("request errored: ", err)
	return &envoy_auth_v2.CheckResponse{
		Status: &rpc.Status{
			Code: int32(rpc.INTERNAL),
		},
		HttpResponse: &envoy_auth_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &envoy_auth_v2.DeniedHttpResponse{
				Status: &_type.HttpStatus{
					Code: _type.StatusCode_InternalServerError,
				},
			},
		},
	}
}

func urlFromRequest(req *envoy_auth_v2.CheckRequest) *url.URL {
	httpRequest := req.GetAttributes().GetRequest().GetHttp()
	url := url.URL{
		Host:     httpRequest.Host,
		Scheme:   httpRequest.Scheme,
		Path:     httpRequest.Path,
		RawQuery: httpRequest.Query,
	}
	if url.Scheme == "" {
		if scheme, ok := httpRequest.GetHeaders()["x-forwarded-proto"]; ok {
			url.Scheme = scheme
		} else {
			url.Scheme = scheme
		}
	}
	return &url
}
