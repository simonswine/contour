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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AuthenticationSpec defines the spec of the CRD
type AuthenticationSpec struct {
	RequestService *AuthenticationRequestService `json:"requestService"`
	Basic          *AuthenticationBasic          `json:"basic"`
}

type AuthenticationRequestService struct {
	// URL defines the endpoint that every request's headers forwarded to.
	// Can cluster internal or external URLs
	URL string `json:"url"`
	// SignInURL defines the public reachable endpoint a user is redirect
	// to, if the AuthURL is requesting htat
	SignInURL string `json:"signInURL"`
}

// Basic is used to perform basic auth using a secret file
type AuthenticationBasic struct {
	// SecretRef references a htpasswd file stored in a secret object
	SecretRef SecretKeySelector `json:"secretRef"`
	// Realm contains the message to display with an appropiate context why the
	// authentication is required
	Realm string `json:"realm"`
}

type SecretKeySelector struct {
	// The name of the secret in the objects's namespace to select from.
	LocalObjectReference `json:",inline"`
	// The key of the secret to select from. Must be a valid secret key.
	// +optional
	Key string `json:"key,omitempty"`
}

type LocalObjectReference struct {
	// Name of the referent.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
	// TODO: Add other useful fields. apiVersion, kind, uid?
	Name string `json:"name"`
}

// AuthenticationStatus reports the current state of the Authentication
type AutenticationStatus struct {
	CurrentStatus string `json:"currentStatus"`
	Description   string `json:"description"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Authentication is an Ingress CRD specificiation
type Authentication struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec   AuthenticationSpec `json:"spec"`
	Status `json:"status"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationList is a list of Authentications
type AuthenticationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []Authentication `json:"items"`
}
