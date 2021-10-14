# add a policy to access data in "my-tool"
# use vault kv put secret/my-tool/config ... to put the data in
# AND YES, the kv put uses secret/my-tool/config and the policy uses secret/data/my-tool/config to point to the same thing
kubectl exec -n vault vault-0 -- sh -c 'echo '"'"'path "secret/data/my-tool/config" { capabilities = ["read"] }'"'"' | vault policy write my-tool -'
kubectl exec -n vault vault-0 -- vault write auth/kubernetes/role/my-tool bound_service_account_names=my-tool-vault-access bound_service_account_namespaces=default policies=my-tool ttl=24h