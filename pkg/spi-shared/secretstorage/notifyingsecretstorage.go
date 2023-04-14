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

package secretstorage

import (
	"context"
	"fmt"

	api "github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type NotifyingSecretStorage struct {
	Client        client.Client
	SecretStorage SecretStorage
	Group         string
	Kind          string
}

var _ SecretStorage = (*NotifyingSecretStorage)(nil)

// Delete implements SecretStorage
func (s *NotifyingSecretStorage) Delete(ctx context.Context, id SecretID) error {
	if err := s.SecretStorage.Delete(ctx, id); err != nil {
		return fmt.Errorf("wrapped storage error: %w", err)
	}

	return s.createDataUpdate(ctx, id)
}

// Get implements SecretStorage
func (s *NotifyingSecretStorage) Get(ctx context.Context, id SecretID) ([]byte, error) {
	var data []byte
	var err error

	if data, err = s.SecretStorage.Get(ctx, id); err != nil {
		return []byte{}, fmt.Errorf("wrapped storage error: %w", err)
	}
	return data, nil
}

// Initialize implements SecretStorage
func (s *NotifyingSecretStorage) Initialize(ctx context.Context) error {
	if err := s.SecretStorage.Initialize(ctx); err != nil {
		return fmt.Errorf("wrapped storage error: %w", err)
	}
	return nil
}

// Store implements SecretStorage
func (s *NotifyingSecretStorage) Store(ctx context.Context, id SecretID, data []byte) error {
	if err := s.SecretStorage.Store(ctx, id, data); err != nil {
		return fmt.Errorf("wrapped storage error: %w", err)
	}

	return s.createDataUpdate(ctx, id)
}

func (s *NotifyingSecretStorage) createDataUpdate(ctx context.Context, id SecretID) error {
	update := &api.SPIAccessTokenDataUpdate{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "data-update-",
			Namespace:    id.Namespace,
		},
		Spec: api.SPIAccessTokenDataUpdateSpec{
			DataOwner: corev1.TypedLocalObjectReference{
				APIGroup: &s.Group,
				Kind:     s.Kind,
				Name:     id.Name,
			},
		},
	}

	err := s.Client.Create(ctx, update)
	if err != nil {
		return fmt.Errorf("error creating data update: %w", err)
	}
	return nil
}
