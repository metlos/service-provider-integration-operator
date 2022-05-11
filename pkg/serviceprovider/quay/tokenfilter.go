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

package quay

import (
	"context"

	api "github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/serviceprovider"
)

type tokenFilter struct {
	metadataProvider *metadataProvider
}

var _ serviceprovider.TokenFilter = (*tokenFilter)(nil)

func (t *tokenFilter) Matches(ctx context.Context, binding *api.SPIAccessTokenBinding, token *api.SPIAccessToken) (bool, error) {
	if token.Status.TokenMetadata == nil {
		return false, nil
	}

	rec, err := t.metadataProvider.FetchRepo(ctx, binding.Spec.RepoUrl, token)
	if err != nil {
		return false, err
	}

	requiredScopes := serviceprovider.GetAllScopes(translateToQuayScopes, &binding.Spec.Permissions)

	for _, s := range requiredScopes {
		requiredScope := Scope(s)

		var testedRecord EntityRecord

		switch requiredScope {
		case ScopeUserRead, ScopeUserAdmin:
			testedRecord = rec.User
		case ScopeOrgAdmin:
			testedRecord = rec.Organization
		default:
			testedRecord = rec.Repository
		}

		if !requiredScope.IsIncluded(testedRecord.PossessedScopes) {
			return false, nil
		}
	}

	return true, nil
}
