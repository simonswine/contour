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

// Package grpc provides a gRPC implementation of the Envoy v2 xDS API.
package grpc

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_auth_v2alpha "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	envoy_service_v2 "github.com/envoyproxy/go-control-plane/envoy/service/load_stats/v2"
	_type "github.com/envoyproxy/go-control-plane/envoy/type"
	rpc "github.com/gogo/googleapis/google/rpc"
	"github.com/sirupsen/logrus"
)

const (
	// somewhat arbitrary limit to handle many, many, EDS streams
	grpcMaxConcurrentStreams = 1 << 20
)

// NewAPI returns a *grpc.Server which responds to the Envoy v2 xDS gRPC API.
func NewAPI(log logrus.FieldLogger, cacheMap map[string]Cache) *grpc.Server {
	opts := []grpc.ServerOption{
		// By default the Go grpc library defaults to a value of ~100 streams per
		// connection. This number is likely derived from the HTTP/2 spec:
		// https://http2.github.io/http2-spec/#SettingValues
		// We need to raise this value because Envoy will open one EDS stream per
		// CDS entry. There doesn't seem to be a penalty for increasing this value,
		// so set it the limit similar to envoyproxy/go-control-plane#70.
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
	}
	g := grpc.NewServer(opts...)
	s := &grpcServer{
		xdsHandler{
			FieldLogger: log,
			resources: map[string]resource{
				clusterType: &CDS{
					Cache: cacheMap[clusterType],
				},
				endpointType: &EDS{
					Cache: cacheMap[endpointType],
				},
				listenerType: &LDS{
					Cache: cacheMap[listenerType],
				},
				routeType: &RDS{
					Cache: cacheMap[routeType],
				},
			},
		},
	}

	v2.RegisterClusterDiscoveryServiceServer(g, s)
	v2.RegisterEndpointDiscoveryServiceServer(g, s)
	v2.RegisterListenerDiscoveryServiceServer(g, s)
	v2.RegisterRouteDiscoveryServiceServer(g, s)
	envoy_auth_v2alpha.RegisterAuthorizationServer(g, s)
	envoy_auth_v2.RegisterAuthorizationServer(g, s)
	return g
}

// grpcServer implements the LDS, RDS, CDS, and EDS, gRPC endpoints.
type grpcServer struct {
	xdsHandler
}

// A resource provides resources formatted as []types.Any.
type resource interface {
	Cache

	// TypeURL returns the typeURL of messages returned from Values.
	TypeURL() string
}

func queryAuthBackend(ctx context.Context, authURL string, headers http.Header) (statusCode int, err error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", authURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header = headers

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

func filterHeaders(rawHeaders map[string]string) http.Header {
	headers := make(http.Header)
	for key, value := range rawHeaders {
		if strings.HasPrefix(key, ":") {
			continue
		}
		headers[key] = []string{value}
	}
	return headers
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

func (s *grpcServer) Check(ctx context.Context, req *envoy_auth_v2.CheckRequest) (*envoy_auth_v2.CheckResponse, error) {
	// retrieve headers
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
	log := s.WithField("module", "auth")

	// only care about git.swine.de for now TODO
	value, ok := headers[":authority"]
	if !ok {
		// TODO: Probably should be error
		return checkResponseOK(log), nil
	}

	// add authority to log
	log = log.WithField("authority", value)
	if value != "kuard.local" {
		return checkResponseOK(log), nil
	}

	authURL := "https://auth.swine.de/oauth2/auth"
	redirectURLRaw := "https://auth.swine.de/oauth2/start"

	redirectURL, err := url.Parse(redirectURLRaw)
	if err != nil {
		return checkResponseError(log, err), nil
	}

	destURL := urlFromRequest(req)
	query := url.Values{
		"rd": []string{destURL.String()},
	}
	redirectURL.RawQuery = query.Encode()

	statusCode, err := queryAuthBackend(ctx, authURL, filterHeaders(headers))
	if err != nil {
		return checkResponseError(log, err), nil
	}

	if statusCode == 401 {
		return checkResponseRedirect(log, redirectURL), nil
	} else if statusCode == 200 {
		return checkResponseOK(log), nil
	}

	return checkResponseError(log, fmt.Errorf("unknown status code %d", statusCode)), nil
}

func (s *grpcServer) FetchClusters(_ context.Context, req *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	return s.fetch(req)
}

func (s *grpcServer) FetchEndpoints(_ context.Context, req *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	return s.fetch(req)
}

func (s *grpcServer) FetchListeners(_ context.Context, req *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	return s.fetch(req)
}

func (s *grpcServer) FetchRoutes(_ context.Context, req *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error) {
	return s.fetch(req)
}

func (s *grpcServer) StreamClusters(srv v2.ClusterDiscoveryService_StreamClustersServer) error {
	return s.stream(srv)
}

func (s *grpcServer) StreamEndpoints(srv v2.EndpointDiscoveryService_StreamEndpointsServer) error {
	return s.stream(srv)
}

func (s *grpcServer) StreamLoadStats(srv envoy_service_v2.LoadReportingService_StreamLoadStatsServer) error {
	return status.Errorf(codes.Unimplemented, "StreamLoadStats unimplemented")
}

func (s *grpcServer) IncrementalClusters(v2.ClusterDiscoveryService_IncrementalClustersServer) error {
	return status.Errorf(codes.Unimplemented, "IncrementalClusters unimplemented")
}

func (s *grpcServer) IncrementalRoutes(v2.RouteDiscoveryService_IncrementalRoutesServer) error {
	return status.Errorf(codes.Unimplemented, "IncrementalRoutes unimplemented")
}

func (s *grpcServer) StreamListeners(srv v2.ListenerDiscoveryService_StreamListenersServer) error {
	return s.stream(srv)
}

func (s *grpcServer) StreamRoutes(srv v2.RouteDiscoveryService_StreamRoutesServer) error {
	return s.stream(srv)
}
