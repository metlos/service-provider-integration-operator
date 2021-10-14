/*
Copyright 2021.

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

package controllers

import (
	"context"
	stderrors "errors"
	"fmt"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	vault "github.com/hashicorp/vault/api"
	api "github.com/redhat-appstudio/service-provider-integration-operator/api/v1beta1"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/config"
	"github.com/redhat-appstudio/service-provider-integration-operator/pkg/sync"
)

var (
	secretDiffOpts = cmp.Options{
		cmpopts.IgnoreFields(corev1.Secret{}, "TypeMeta", "ObjectMeta"),
	}
)

// AccessTokenSecretReconciler reconciles a AccessTokenSecret object
type AccessTokenSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	syncer sync.Syncer
}

func NewAccessTokenSecretReconciler(cl client.Client, scheme *runtime.Scheme) *AccessTokenSecretReconciler {
	return &AccessTokenSecretReconciler{
		Client: cl,
		Scheme: scheme,
		syncer: sync.New(cl, scheme),
	}
}

// TODO define this properly once we know more
type accessToken map[string]string

//+kubebuilder:rbac:groups=appstudio.redhat.com,resources=accesstokensecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=appstudio.redhat.com,resources=accesstokensecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=appstudio.redhat.com,resources=accesstokensecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=impersonate

func (r *AccessTokenSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	lg := log.FromContext(ctx, "AccessTokenSecret", req.NamespacedName)

	ats := api.AccessTokenSecret{}

	if err := r.Get(ctx, req.NamespacedName, &ats); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	if ats.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	saToken, err := r.getServiceAccountToken(log.IntoContext(ctx, lg), &ats)
	if err != nil {
		// TODO update the status with the failure
		return ctrl.Result{}, err
	}

	token, err := readDataFromVault(log.IntoContext(ctx, lg.WithValues("ImpersonatedAs", ats.Spec.ServiceAccount)), saToken, ats.Spec.AccessTokenId)
	if err != nil {
		// TODO update the status with the failure
		return ctrl.Result{}, err
	}

	err = nil
	if ats.Spec.Target.ConfigMap != nil {
		err = r.saveTokenAsConfigMap(ctx, &ats, &token, ats.Spec.Target.ConfigMap)
	} else if ats.Spec.Target.Secret != nil {
		err = r.saveTokenAsSecret(ctx, &ats, &token, ats.Spec.Target.Secret)
	} else if ats.Spec.Target.Containers != nil {
		err = r.injectTokenIntoPods(ctx, &ats, &token, ats.Spec.Target.Containers)
	} else {
		return ctrl.Result{}, stderrors.New("AccessTokenSecret needs to specify a valid target")
	}

	// TODO update the status with the potential failure

	return ctrl.Result{}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *AccessTokenSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.AccessTokenSecret{}).
		Watches(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
			OwnerType: &api.AccessTokenSecret{},
		}).
		Watches(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForOwner{
			OwnerType: &api.AccessTokenSecret{},
		}).
		Watches(&source.Kind{Type: &appsv1.Deployment{}}, handler.EnqueueRequestsFromMapFunc(func(o client.Object) []reconcile.Request {
			// TODO look for some label for example
			return []reconcile.Request{}
		})).
		Complete(r)
}

func (r *AccessTokenSecretReconciler) getServiceAccountToken(ctx context.Context, acs *api.AccessTokenSecret) (string, error) {
	sa := acs.Spec.ServiceAccount
	if sa.Name != "" {
		if sa.Namespace == "" {
			sa.Namespace = acs.GetNamespace()
		}

		// get the service account
		saObj := corev1.ServiceAccount{}
		if err := r.Get(ctx, client.ObjectKey{Name: sa.Name, Namespace: sa.Namespace}, &saObj); err != nil {
			return "", err
		}

		// get the token from its secret
		if len(saObj.Secrets) == 0 {
			return "", fmt.Errorf("the service account %s:%s doesn't have any secrets with tokens", sa.Name, sa.Namespace)
		}

		secret := corev1.Secret{}
		for _, s := range saObj.Secrets {
			key := client.ObjectKey{Name: s.Name, Namespace: s.Namespace}
			if key.Namespace == "" {
				key.Namespace = saObj.Namespace
			}
			if err := r.Get(ctx, key, &secret); err != nil {
				continue
			}

			if string(secret.Data["namespace"]) == saObj.Namespace {
				return string(secret.Data["token"]), nil
			}
		}

		return "", fmt.Errorf("could not find the secret with a token for %s:%s", sa.Name, sa.Namespace)
	} else {
		// there is no service account configured, let's just use ours
		config.ServiceAccountTokenFile()
		jwt, err := os.ReadFile(config.ServiceAccountTokenFile())
		if err != nil {
			return "", fmt.Errorf("unable to read file containing service account token: %w", err)
		}

		return string(jwt), nil
	}
}

func readDataFromVault(ctx context.Context, saToken string, tokenId string) (accessToken, error) {
	conf := vault.Config{
		Address: config.VaultUrl(),
	}

	vcl, err := vault.NewClient(&conf)
	if err != nil {
		return accessToken{}, err
	}

	resp, err := vcl.Logical().Write("auth/kubernetes/login", map[string]interface{}{
		"jwt": saToken,
		// TODO this is obviously hardcoded
		//"role": "my-tool",
	})
	if err != nil {
		return accessToken{}, fmt.Errorf("unable to login using Kubernetes auth: %w", err)
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return accessToken{}, fmt.Errorf("login response from Vault did not return client token")
	}

	vcl.SetToken(resp.Auth.ClientToken)

	sec, err := vcl.Logical().Read(tokenId)
	if err != nil {
		return accessToken{}, err
	}
	if sec == nil || sec.Data["data"] == nil {
		return accessToken{}, nil
	}

	ret := accessToken{}

	switch d := sec.Data["data"].(type) {
	case map[string]interface{}:
		for k, v := range d {
			switch val := v.(type) {
			case string:
				ret[k] = string(val)
			}
		}
	}

	return ret, nil
}

func (r *AccessTokenSecretReconciler) saveTokenAsConfigMap(ctx context.Context, owner *api.AccessTokenSecret, token *accessToken, spec *api.AccessTokenTargetConfigMap) error {
	cm := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        spec.Name,
			Namespace:   owner.GetNamespace(),
			Labels:      spec.Labels,
			Annotations: spec.Annotations,
		},
		Data: *token,
	}

	_, _, err := r.syncer.Sync(ctx, owner, cm, secretDiffOpts)
	return err
}

func (r *AccessTokenSecretReconciler) saveTokenAsSecret(ctx context.Context, owner *api.AccessTokenSecret, token *accessToken, spec *api.AccessTokenTargetSecret) error {
	data := map[string][]byte{}
	for k, v := range *token {
		data[k] = []byte(v)
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        spec.Name,
			Namespace:   owner.GetNamespace(),
			Labels:      spec.Labels,
			Annotations: spec.Annotations,
		},
		Data: data,
	}

	_, _, err := r.syncer.Sync(ctx, owner, secret, secretDiffOpts)
	return err
}

func (r *AccessTokenSecretReconciler) injectTokenIntoPods(ctx context.Context, owner *api.AccessTokenSecret, token *accessToken, spec *api.AccessTokenTargetContainers) error {
	// TODO implement
	return stderrors.New("injection into pods not implemented")
}
