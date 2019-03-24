package authentication

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	envoy_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/sirupsen/logrus"
)

var _ Authenticator = &RequestService{}

// RequestService implements a HTTP Authentication Service client
type RequestService struct {
	url       *url.URL
	signInURL *url.URL
}

// NewRequestService creates a new HTTP Authentication Service client
func NewRequestService(urlIn string, signInURLIn string) (*RequestService, error) {
	url, err := url.Parse(urlIn)
	if err != nil {
		return nil, err
	}

	signInURL, err := url.Parse(signInURLIn)
	if err != nil {
		return nil, err
	}

	return &RequestService{
		url:       url,
		signInURL: signInURL,
	}, nil

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

// Check implements the authentication check for RequestService Auth
func (r *RequestService) Check(log *logrus.Entry, ctx context.Context, req *envoy_auth_v2.CheckRequest) (*envoy_auth_v2.CheckResponse, error) {
	log = log.WithField("auth", "request_service")

	// retrieve headers
	headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()

	statusCode, err := queryAuthBackend(ctx, r.url.String(), filterHeaders(headers))
	if err != nil {
		return checkResponseError(log, err), nil
	}

	if statusCode == 401 {
		return checkResponseRedirect(log, r.signInURL), nil
	} else if statusCode >= 200 && statusCode < 300 {
		return checkResponseOK(log), nil
	}

	return checkResponseError(log, fmt.Errorf("unknown status code %d", statusCode)), nil
}
