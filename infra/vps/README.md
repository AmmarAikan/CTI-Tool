# VPS Infrastructure Boundary

This directory records the intended cloud deployment without pretending that a remote server already exists.

The project will use upstream, version-pinned deployments for Wazuh and MISP instead of copying their large Compose stacks into this repository. After SSH access, this directory may contain only project-owned overlays, firewall/VPN documentation, health checks, sanitized inventories, and backup/restore scripts. Upstream credentials, certificates, database files, captured honeypot data, and generated secrets must remain outside Git.

Before remote work, read:

- `docs/architecture/cloud_distributed_architecture.md`
- `docs/operations/vps_deployment_plan.md`
- `docs/api/external_feed_contract.md`
- `docs/api/dionaea_sensor_contract.md`

Remote completion must be supported by a dated, sanitized acceptance record. Configuration files alone are not deployment evidence.
