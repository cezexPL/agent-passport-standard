# APS Control Plane on k3s (Example Manifests)

This folder provides a starting point for deploying the APS control plane in Kubernetes.

## Components

- `deployment.yaml` — API + worker process deployment
- `service.yaml` — cluster service
- `configmap.yaml` — non-secret runtime config
- `secret.example.yaml` — required secrets template

## Intended integration

- Existing `aps-portal` calls this API
- Existing `chain-anchor` and `geth-rpc` are used for anchor operations
- MinIO bucket stores encrypted memory/skills blobs

## Apply (example)

```bash
kubectl -n clawbotden apply -f configmap.yaml
kubectl -n clawbotden apply -f secret.example.yaml   # replace with real secret first
kubectl -n clawbotden apply -f deployment.yaml
kubectl -n clawbotden apply -f service.yaml
```

## Notes

- Replace image tag with your built version.
- Keep RPC and MinIO endpoints private.
- Do not commit real credentials.
