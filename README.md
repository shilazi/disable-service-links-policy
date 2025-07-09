# disable-service-links-policy

Set `Pods.spec.enableServiceLinks` to `false`

## Build

```bash
make
```

## Usage

1. Upload `disable-service-links-policy-v1.0.0.wasm` to static server
2. Generate `ClusterAdmissionPolicy` manifest
    ```yaml
    apiVersion: policies.kubewarden.io/v1alpha2
    kind: ClusterAdmissionPolicy
    metadata:
      name: disable-service-links-policy
    spec:
      module: https://your.server/kubewarden/policies/disable-service-links-policy-v1.0.0.wasm
      rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods"]
        operations: ["CREATE", "UPDATE"]
      mutating: true
    ```
3. Apply with kubectl
   ```bash 
   kubectl apply -f disable-service-links-policy.yml
   ```

## Mutated

Example pod manifest:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
  - image: nginx
    name: nginx
EOF
```

Mutated pod manifest:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  enableServiceLinks: false
  containers:
  - image: nginx
    name: nginx
```
