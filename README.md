# Northfoot Project

Northfoot project is an "edge CA" designed for homelabs, 5G base stations and large cybersecurity companies.

## Architecture

### Signers

As an "edge CA," Northfoot project holds various `Signers`. The configuration for these signers is stored
in a database, but the key material is generated at runtime and held only in memory.

The following `Signers` are imagined:

- `InMem`: A self-signed CA is generated in memory for the lifetime of the program
- `File`: A CA Private Key and CSR are generated in memory, then signed with a cert/key pair loaded from the filesystem.
- `HSM`: A CA Private Key and CSR are generated in memory, then signed by sending the CSR to an HSM
- `Remote` A CA Private Key and CSR are generated in memory, then signed by sending the CSR to another instance of Northfoot

### API

An instance of Northfoot project is designed to run in every one of
your edge locations, issuing certs quickly to workloads over an API. 
For maximum compatibility and speed, the Northfoot API supports 
json over HTTP, raw proto over HTTP/2 and gRPC. Authentication expects
either static bearer tokens or SPIFFE SVIDs.

