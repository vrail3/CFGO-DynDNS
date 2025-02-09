# CFGO-DynDNS

<p align="center">
  <img src="CFGO-DynDNS.svg" alt="CFGO-DynDNS Logo" width="200" height="200">
</p>

Dynamic DNS Client for Cloudflare written in Go. Updates A and AAAA records for your domain using Cloudflare's API.

## Features

- Updates both IPv4 (A) and IPv6 (AAAA) records
- Simple HTTP API interface
- Status endpoint for monitoring
- Docker support with multi-arch images (amd64, arm64)
- Healthcheck support
- Secure app key authentication

## Quick Start

### Docker

```bash
docker run -d \
  -p 80:8080 \
  -e CF_ZONE="example.com" \
  -e CF_RECORD="www.example.com" \
  -e CF_API_KEY="your-cloudflare-api-token" \
  -e APP_KEY="your-app-key" \
  ghcr.io/vrail3/cfgo-dyndns:latest
```

### Docker Compose

```yaml
services:
  cloudflare-dyndns:
    image: ghcr.io/vrail3/cfgo-dyndns:latest
    container_name: cfgo-dyndns
    ports:
      - "80:8080"
    restart: unless-stopped
    environment:
      CF_ZONE: "example.com"
      CF_RECORD: "dyndns.example.com"
      CF_API_KEY: "your-cloudflare-api-token"
      APP_KEY: "your-app-key"
```

## Configuration

Environment Variables:

- `CF_ZONE`: Your domain (e.g., "example.com")
- `CF_RECORD`: Full record name to update (e.g., "dyndns.example.com")
- `CF_API_KEY`: Cloudflare API Token (needs Zone.Zone Read and Zone.DNS Edit permissions)
- `APP_KEY`: Secret key for client authentication

## API Usage

### Update DNS Records

```bash
# Update IPv4
curl "http://localhost:8080/?key=your-app-key&ipv4=1.2.3.4"

# Update IPv6
curl "http://localhost:8080/?key=your-app-key&ipv6=2001:db8::1"

# Update both
curl "http://localhost:8080/?key=your-app-key&ipv4=1.2.3.4&ipv6=2001:db8::1"
```

### Check Status

```bash
curl "http://localhost:8080/status"
```

Response:

```json
{
  "last_updated": "2024-01-20T15:04:05Z",
  "ipv4": "1.2.3.4",
  "ipv6": "2001:db8::1",
  "status": "success"
}
```

## FRITZ!Box Configuration

- Update URL: `http://your-server:80/?key=<pass>&ipv4=<ipaddr>&ipv6=<ip6addr>`
- Domain Name: Your dynamic DNS domain (e.g., dyndns.example.com)
- Username: any value
- Password: Your app key
