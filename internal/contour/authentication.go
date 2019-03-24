// Copyright © 2018 Heptio
// Licensed under the Apache License, Version 2.0 (the "License");
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

package contour

import (
	"sync"

	"github.com/heptio/contour/internal/authentication"
	"github.com/heptio/contour/internal/dag"
)

// AuthenticationCache manages the contents of the gRPC CDS cache.
type AuthenticationCache struct {
	mu      sync.Mutex
	values  map[meta]authentication.Authenticator
	waiters []chan int
	last    int
}

// Update replaces the contents of the cache with the supplied map.
func (c *AuthenticationCache) Update(v map[meta]authentication.Authenticator) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.values = v
}

// LookUp retrieves a cached authenticator instance
func (c *AuthenticationCache) LookUp(namespace, name string) (authentication.Authenticator, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	v, ok := c.values[meta{namespace, name}]
	return v, ok
}

func visitAuthentications(root dag.Vertex) map[meta]authentication.Authenticator {
	av := authenticationVisitor{
		authentications: make(map[meta]authentication.Authenticator),
	}
	av.visit(root)
	return av.authentications
}

type meta [2]string
type authenticationVisitor struct {
	authentications map[meta]authentication.Authenticator
}

func (v *authenticationVisitor) visit(vertex dag.Vertex) {
	switch a := vertex.(type) {
	case *dag.Authentication:
		var auth authentication.Authenticator
		if b := a.Object.Spec.Basic; b != nil {
			authBasic, err := authentication.NewBasic(
				b.Realm,
				a.BasicSecret.Data()[b.SecretRef.Key],
			)
			if err != nil {
				// TODO: Don't panic
				panic(err)
			}

			auth = authBasic
		}

		if r := a.Object.Spec.RequestService; r != nil {
			authRequestService, err := authentication.NewRequestService(
				r.URL,
				r.SignInURL,
			)
			if err != nil {
				// TODO: Don't panic
				panic(err)
			}
			auth = authRequestService
		}

		if auth != nil {
			v.authentications[[2]string{a.Namespace(), a.Name()}] = auth
		}
	default:
		// nothing
	}

	// recurse into children of v
	vertex.Visit(v.visit)
}
