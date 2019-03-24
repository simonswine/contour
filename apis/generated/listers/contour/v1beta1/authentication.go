/*
Copyright 2019 Heptio

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by lister-gen. DO NOT EDIT.

package v1beta1

import (
	v1beta1 "github.com/heptio/contour/apis/contour/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// AuthenticationLister helps list Authentications.
type AuthenticationLister interface {
	// List lists all Authentications in the indexer.
	List(selector labels.Selector) (ret []*v1beta1.Authentication, err error)
	// Authentications returns an object that can list and get Authentications.
	Authentications(namespace string) AuthenticationNamespaceLister
	AuthenticationListerExpansion
}

// authenticationLister implements the AuthenticationLister interface.
type authenticationLister struct {
	indexer cache.Indexer
}

// NewAuthenticationLister returns a new AuthenticationLister.
func NewAuthenticationLister(indexer cache.Indexer) AuthenticationLister {
	return &authenticationLister{indexer: indexer}
}

// List lists all Authentications in the indexer.
func (s *authenticationLister) List(selector labels.Selector) (ret []*v1beta1.Authentication, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.Authentication))
	})
	return ret, err
}

// Authentications returns an object that can list and get Authentications.
func (s *authenticationLister) Authentications(namespace string) AuthenticationNamespaceLister {
	return authenticationNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// AuthenticationNamespaceLister helps list and get Authentications.
type AuthenticationNamespaceLister interface {
	// List lists all Authentications in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1beta1.Authentication, err error)
	// Get retrieves the Authentication from the indexer for a given namespace and name.
	Get(name string) (*v1beta1.Authentication, error)
	AuthenticationNamespaceListerExpansion
}

// authenticationNamespaceLister implements the AuthenticationNamespaceLister
// interface.
type authenticationNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all Authentications in the indexer for a given namespace.
func (s authenticationNamespaceLister) List(selector labels.Selector) (ret []*v1beta1.Authentication, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1beta1.Authentication))
	})
	return ret, err
}

// Get retrieves the Authentication from the indexer for a given namespace and name.
func (s authenticationNamespaceLister) Get(name string) (*v1beta1.Authentication, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1beta1.Resource("authentication"), name)
	}
	return obj.(*v1beta1.Authentication), nil
}
