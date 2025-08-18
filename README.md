# Omni vSphere Provider

An infrastructure provider for Omni that integrates with vSphere infrastructure.

## Features

- Cluster creation and management
- Integration with Omni API
- Secure service account authentication
- Containerized deployment

## Quick Start

Build and push the image to a local registry, then run the provider container.

```bash
make image-omni-infra-provider-vsphere REGISTRY=<registry> USERNAME=<username> IMAGE_TAG=<tag> PUSH=true

docker run -d --name omni-infra-provider-vsphere --network host \
  -e OMNI_CA_BUNDLE="<base64-encoded-PEM-CA>" \
  -e OMNI_SERVICE_ACCOUNT_KEY="${OMNI_SERVICE_ACCOUNT_KEY}" \
  -e OMNI_ENDPOINT="${OMNI_ENDPOINT}" \
  -e VSPHERE_URL="https://<vcenter-ip-or-host>/sdk" \
  -e VSPHERE_USERNAME="<vsphere-username>" \
  -e VSPHERE_PASSWORD="<vsphere-password>" \
  <registry>/<username>/omni-infra-provider-vsphere:<tag> \
  --insecure-skip-verify
```

Notes:

- __OMNI_CA_BUNDLE__: base64 of a PEM CA. Alternatively, use `OMNI_CA_BUNDLE_PATH=/path/to/ca.pem`.
- __OMNI_ENDPOINT__ and __OMNI_SERVICE_ACCOUNT_KEY__: your Omni API endpoint and service account key.
- __VSPHERE_URL/USERNAME/PASSWORD__: vCenter endpoint and credentials.
- `--insecure-skip-verify` disables TLS verification for the provider’s outbound requests. Remove it in secure environments.

## Prerequisites

- Go 1.24
- Docker
- Access to Omni API
- Service account credentials

## Building

```bash
go build -o omni-vsphere-provider
```

## Running

### Local Development

```bash
./omni-vsphere-provider \
    --endpoint="https://your-omni-endpoint" \
    --service-account-key="your-service-account-key"
```

### Docker

```bash
docker build -t omni-vsphere-provider .

docker run -d \
    --name omni-vsphere-provider \
    --restart=always \
    --network host \
    -e OMNI_ENDPOINT="https://your-omni-endpoint" \
    -e OMNI_SERVICE_ACCOUNT_KEY="your-service-account-key" \
    omni-vsphere-provider
```

## Configuration

The provider accepts the following configuration options:

- `--api-port`: Port to listen on (default: 50042)
- `--api-addr`: Address to listen on (default: 0.0.0.0)
- `--endpoint`: Omni API endpoint
- `--service-account-key`: Omni service account key
- `--vsphere-url`: vSphere API URL
- `--vsphere-user`: vSphere username
- `--vsphere-password`: vSphere password

## Security

- All API communication is encrypted
- Service account credentials should be stored securely
- Use environment variables for sensitive configuration

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT
