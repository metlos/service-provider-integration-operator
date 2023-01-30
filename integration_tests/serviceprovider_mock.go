//
// Copyright (c) 2021 Red Hat, Inc.
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

package integrationtests

import (
	"context"

	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/serviceprovider"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/spi-shared/config"

	api "github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// TestServiceProvider is an implementation of the serviceprovider.ServiceProvider interface that can be modified by
// supplying custom implementations of each of the interface methods. It provides dummy implementations of them, too, so
// that no null pointer dereferences should occur under normal operation.
type TestServiceProvider struct {
	LookupTokenImpl           func(context.Context, client.Client, *api.SPIAccessTokenBinding) (*api.SPIAccessToken, error)
	PersistMetadataImpl       func(context.Context, client.Client, *api.SPIAccessToken) error
	GetBaseUrlImpl            func() string
	GetTypeImpl               func() config.ServiceProviderType
	CheckRepositoryAccessImpl func(context.Context, client.Client, *api.SPIAccessCheck) (*api.SPIAccessCheckStatus, error)
	MapTokenImpl              func(context.Context, *api.SPIAccessTokenBinding, *api.SPIAccessToken, *api.Token) (serviceprovider.AccessTokenMapper, error)
	ValidateImpl              func(context.Context, serviceprovider.Validated) (serviceprovider.ValidationResult, error)
	CustomizeReset            func(provider *TestServiceProvider)
	DownloadFileCapability    func() serviceprovider.DownloadFileCapability
	RefreshTokenCapability    func() serviceprovider.RefreshTokenCapability
	OAuthCapability           func() serviceprovider.OAuthCapability
}

// TestCapability is test implementation for capabilities that Service Provider can have.
// Currently it aggregates DownloadFileCapability and OAuthCapability. All of these have valid results (i.e. do not result in any errors).
type TestCapability struct{}

func (f TestCapability) DownloadFile(context.Context, string, string, string, *api.SPIAccessToken, int) (string, error) {
	return "abcdefg", nil
}

func (c TestCapability) GetOAuthEndpoint() string {
	return ITest.OperatorConfiguration.BaseUrl + "/test/oauth"
}

func (c TestCapability) OAuthScopesFor(permissions *api.Permissions) []string {
	return []string{}
}

var _ serviceprovider.ServiceProvider = (*TestServiceProvider)(nil)

func (t TestServiceProvider) CheckRepositoryAccess(ctx context.Context, cl client.Client, accessCheck *api.SPIAccessCheck) (*api.SPIAccessCheckStatus, error) {
	if t.CheckRepositoryAccessImpl == nil {
		return &api.SPIAccessCheckStatus{}, nil
	}
	return t.CheckRepositoryAccessImpl(ctx, cl, accessCheck)
}

func (t TestServiceProvider) LookupToken(ctx context.Context, cl client.Client, binding *api.SPIAccessTokenBinding) (*api.SPIAccessToken, error) {
	if t.LookupTokenImpl == nil {
		return nil, nil
	}
	return t.LookupTokenImpl(ctx, cl, binding)
}

func (t TestServiceProvider) PersistMetadata(ctx context.Context, cl client.Client, token *api.SPIAccessToken) error {
	if t.PersistMetadataImpl == nil {
		return nil
	}

	return t.PersistMetadataImpl(ctx, cl, token)
}

func (t TestServiceProvider) GetBaseUrl() string {
	if t.GetBaseUrlImpl == nil {
		return "test-provider://base"
	}
	return t.GetBaseUrlImpl()
}

func (t TestServiceProvider) GetType() config.ServiceProviderType {
	if t.GetTypeImpl == nil {
		return config.ServiceProviderType{Name: "TestServiceProvider", DefaultBaseUrl: "test-provider://acme"}
	}
	return t.GetTypeImpl()
}

func (t TestServiceProvider) GetDownloadFileCapability() serviceprovider.DownloadFileCapability {
	if t.DownloadFileCapability == nil {
		return nil
	}
	return t.DownloadFileCapability()
}

func (t TestServiceProvider) GetRefreshTokenCapability() serviceprovider.RefreshTokenCapability {
	if t.RefreshTokenCapability == nil {
		return nil
	}
	return t.RefreshTokenCapability()
}

func (t TestServiceProvider) GetOAuthCapability() serviceprovider.OAuthCapability {
	if t.OAuthCapability == nil {
		return nil
	}
	return t.OAuthCapability()
}

func (t TestServiceProvider) MapToken(ctx context.Context, binding *api.SPIAccessTokenBinding, token *api.SPIAccessToken, tokenData *api.Token) (serviceprovider.AccessTokenMapper, error) {
	if t.MapTokenImpl == nil {
		return serviceprovider.AccessTokenMapper{}, nil
	}

	return t.MapTokenImpl(ctx, binding, token, tokenData)
}

func (t TestServiceProvider) Validate(ctx context.Context, validated serviceprovider.Validated) (serviceprovider.ValidationResult, error) {
	if t.ValidateImpl == nil {
		return serviceprovider.ValidationResult{}, nil
	}

	return t.ValidateImpl(ctx, validated)
}

func (t *TestServiceProvider) Reset() {
	t.LookupTokenImpl = nil
	t.GetBaseUrlImpl = nil
	t.GetTypeImpl = nil
	t.PersistMetadataImpl = nil
	t.CheckRepositoryAccessImpl = nil
	t.MapTokenImpl = nil
	t.ValidateImpl = nil
	t.DownloadFileCapability = nil
	t.RefreshTokenCapability = nil
	t.OAuthCapability = nil
	if t.CustomizeReset != nil {
		t.CustomizeReset(t)
	}
}

// LookupConcreteToken returns a function that can be used as the TestServiceProvider.LookupTokenImpl that just returns
// a freshly loaded version of the provided token. The token is a pointer to a pointer to the token so that this can
// also support lazily initialized tokens.
func LookupConcreteToken(tokenPointer **api.SPIAccessToken) func(ctx context.Context, cl client.Client, binding *api.SPIAccessTokenBinding) (*api.SPIAccessToken, error) {
	return func(ctx context.Context, cl client.Client, binding *api.SPIAccessTokenBinding) (*api.SPIAccessToken, error) {
		if *tokenPointer == nil {
			return nil, nil
		}

		freshToken := &api.SPIAccessToken{}
		if err := cl.Get(ctx, client.ObjectKeyFromObject(*tokenPointer), freshToken); err != nil {
			return nil, err
		}
		return freshToken, nil
	}
}

// PersistConcreteMetadata returns a function that can be used as the TestServiceProvider.PersistMetadataImpl that
// stores the provided metadata to any token.
func PersistConcreteMetadata(metadata *api.TokenMetadata) func(context.Context, client.Client, *api.SPIAccessToken) error {
	return func(ctx context.Context, cl client.Client, token *api.SPIAccessToken) error {
		token.Status.TokenMetadata = metadata
		return cl.Status().Update(ctx, token)
	}
}
