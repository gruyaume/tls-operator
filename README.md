# tls-operator

## Description

Provider of self-signed certificates to charms that require them.

## Usage

```bash
juju deploy tls-operator --trust
```

# Configs

```bash
juju config tls-operator ca-cert-subject=<your CA subject name>
```

## Relations

```bash
juju relate tls-operator <other charm>
```

## OCI Images

Dummy OCI Image