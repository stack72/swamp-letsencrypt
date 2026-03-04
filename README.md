# swamp-letsencrypt

A [swamp](https://github.com/systeminit/swamp) extension model for managing Let's Encrypt TLS certificates using DNS-01 challenges.

## Prerequisites

- [swamp](https://github.com/systeminit/swamp) installed
- Ability to create DNS TXT records for your domain (the model logs the required records and polls until they appear)

## Setup

1. Install the extension in your swamp project:

   ```bash
   swamp extension pull @stack72/letsencrypt-certificate
   ```

2. Create a vault for storing sensitive data (account keys, certificate private keys):

   ```bash
   swamp vault create local_encryption default
   ```

3. Create a model instance:

   ```bash
   swamp model create @stack72/letsencrypt-certificate my-cert
   ```

4. Edit the generated input YAML (`swamp model edit my-cert`) with your domain and email:

   ```yaml
   globalArguments:
     domain: "example.com"
     altNames: []
     email: "admin@example.com"
     staging: true
   methods:
     create:
       arguments: {}
     status:
       arguments: {}
     renew:
       arguments: {}
     revoke:
       arguments: {}
   ```

   Set `staging: false` when you're ready to issue real certificates from Let's Encrypt production.

## Usage

### Issue a certificate

```bash
swamp model method run my-cert create --verbose
```

This will:

1. Generate an ACME account key and register with Let's Encrypt
2. Create a certificate order for your domain
3. Log the DNS TXT record you need to create, e.g.:

   ```
   Create TXT record: _acme-challenge.example.com → "abc123..."
   ```

4. Poll DNS every 10 seconds (up to 10 minutes) until the record is found
5. Complete the challenge, generate a CSR, and download the signed certificate
6. Store the account and certificate data (private keys go to the vault)

### Check certificate status

```bash
swamp model method run my-cert status --verbose
```

Reports the certificate expiry date, days remaining, and whether renewal is needed (< 30 days).

### Renew a certificate

```bash
swamp model method run my-cert renew --verbose
```

Uses the existing ACME account to request a new certificate. Same DNS-01 challenge flow as `create` — you'll need to update the TXT record with the new value.

### Revoke a certificate

```bash
swamp model method run my-cert revoke --verbose
```

Revokes the certificate via the ACME protocol.

## Global Arguments

| Argument   | Type       | Default | Description                              |
|------------|------------|---------|------------------------------------------|
| `domain`   | `string`   | —       | Primary domain for the certificate       |
| `altNames` | `string[]` | `[]`    | Additional Subject Alternative Names     |
| `email`    | `string`   | —       | Contact email for the ACME account       |
| `staging`  | `boolean`  | `true`  | Use Let's Encrypt staging vs production  |

## Stored Resources

| Resource      | Fields                                                        |
|---------------|---------------------------------------------------------------|
| `account`     | `accountUrl`, `accountKey` (sensitive)                        |
| `certificate` | `domain`, `certificate`, `chain`, `privateKey` (sensitive), `expiry`, `issuedAt` |

Access stored data via CEL expressions:

```
${{ data.latest("my-cert", "certificate").attributes.domain }}
${{ data.latest("my-cert", "certificate").attributes.expiry }}
```
