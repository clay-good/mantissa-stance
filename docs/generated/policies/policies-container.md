# CONTAINER Policies

Security policies for CONTAINER resources.

## Critical Severity

### container-001

**Name:** Container images should not have critical vulnerabilities

Container images with critical vulnerabilities pose significant security
risks. Critical CVEs often have known exploits and can lead to complete
system compromise. Images should be regularly scanned and updated.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 RA-5
- cis-docker 4.1
- pci-dss 6.3.3

**Remediation:**
1. Review the list of critical vulnerabilities
2. Check if newer base images are available
3. Update vulnerable packages:
   - For OS packages: apt-get update && apt-get upgrade
   - For language packages: Update dependency files
4. Rebuild the container image
5. Re-scan to verify vulnerabilities are fixed
6. Update deployment manifests to use new image


### container-003

**Name:** Container images should not have CISA KEV vulnerabilities

The CISA Known Exploited Vulnerabilities (KEV) catalog contains CVEs
that are actively exploited in the wild. These vulnerabilities must
be addressed with highest priority as they represent real threats.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 RA-5
- cisa-bod KEV

**Remediation:**
1. Review KEV vulnerabilities immediately
2. CISA mandates federal agencies fix KEV vulns by due date
3. Check CISA KEV catalog for remediation deadlines
4. Update or patch affected packages immediately
5. If no fix available, implement compensating controls
6. Consider replacing affected components if necessary
7. Document remediation actions taken


### container-010

**Name:** Container images should not contain sensitive files

Container images should not contain secrets, credentials, or private
keys. These files may be exposed through image layers, registries,
or at runtime, leading to credential compromise.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 IA-5
- cis-docker 4.10
- owasp A01

**Remediation:**
1. Scan image for secrets using tools like Trivy or Gitleaks
2. Remove sensitive files from Dockerfile
3. Use .dockerignore to exclude secrets from build context
4. Use multi-stage builds to avoid copying secrets
5. Pass secrets via environment variables or mounted volumes
6. Use secrets management systems (Vault, K8s secrets, etc.)
7. Rotate any exposed credentials immediately


### container-014

**Name:** Container images should not contain malware

Container images must be free of malware, cryptominers, and other
malicious software. Malware in images can compromise infrastructure
and lead to data theft or resource abuse.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 SI-3
- cis-docker 4.4
- pci-dss 5.2

**Remediation:**
1. Quarantine the affected image immediately
2. Investigate source of malware
3. Check build pipeline for compromise
4. Scan base images and dependencies
5. Rebuild image from trusted sources
6. Scan all related images for infection
7. Report incident per security policies


## High Severity

### container-002

**Name:** Container images should minimize high severity vulnerabilities

High severity vulnerabilities can be exploited to gain unauthorized
access or cause significant damage. While some high CVEs may be
acceptable with compensating controls, they should be minimized.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 RA-5
- cis-docker 4.1

**Remediation:**
1. Review high severity vulnerabilities
2. Prioritize based on EPSS scores and KEV catalog
3. Update vulnerable packages where fixes are available
4. For unfixed vulns, assess risk and apply mitigations
5. Document accepted risks with justification
6. Re-scan after remediation


### container-006

**Name:** Container images should be from approved registries

Images should only be pulled from trusted, approved container registries.
Using images from unapproved sources increases supply chain attack risk
and may introduce malicious or vulnerable code.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 SA-12
- cis-docker 4.6
- slsa Source

**Remediation:**
1. Identify the current image registry
2. Check if registry is on approved list
3. If not, find equivalent image in approved registry
4. Or mirror the image to approved registry after verification
5. Update image references in manifests
6. Implement registry allowlists in admission controllers


### container-007

**Name:** Container images should be signed

Container image signatures verify authenticity and integrity.
Unsigned images cannot be verified as originating from trusted
sources and may have been tampered with.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 SA-12
- slsa Provenance
- cis-docker 4.5

**Remediation:**
1. Set up image signing in CI/CD pipeline
2. Use Cosign, Notary, or similar signing tool
3. Sign images after successful build and scan
4. Store signatures in registry or transparency log
5. Configure admission controllers to verify signatures
6. Document signing key management procedures


### container-009

**Name:** Container images should not run as root

Running containers as root increases the impact of container escapes.
If an attacker escapes the container, they may gain root on the host.
Images should specify a non-root USER in the Dockerfile.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 AC-6
- cis-docker 4.1
- cis-kubernetes 5.2.6

**Remediation:**
1. Review Dockerfile for USER instruction
2. Create non-root user in Dockerfile:
   RUN adduser --disabled-password --gecos '' appuser
   USER appuser
3. Ensure file permissions allow non-root access
4. Update entrypoint scripts for non-root execution
5. Test application functionality as non-root user
6. Use runAsNonRoot in Kubernetes security context


### container-013

**Name:** Container images should not have high EPSS score vulnerabilities

EPSS (Exploit Prediction Scoring System) predicts the likelihood of
a vulnerability being exploited. Vulnerabilities with high EPSS scores
(>10%) require urgent attention regardless of CVSS severity.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 RA-5
- first EPSS

**Remediation:**
1. Review vulnerabilities with high EPSS scores
2. EPSS >10% indicates likely exploitation
3. Prioritize these over low-EPSS critical CVEs
4. Apply patches or mitigations immediately
5. Monitor for exploitation attempts
6. Consider compensating controls while patching


## Medium Severity

### container-004

**Name:** Container images should fix vulnerabilities with available patches

When vulnerability fixes are available, they should be applied.
Running images with known fixable vulnerabilities indicates poor
patch management and increases exposure window unnecessarily.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 SI-2
- cis-docker 4.1

**Remediation:**
1. Review vulnerabilities with available fixes
2. Update package managers and dependencies
3. For OS packages: apt-get update && apt-get upgrade
4. For Python: pip install --upgrade package
5. For Node.js: npm update or npm audit fix
6. Rebuild and test container image
7. Deploy updated image to environments


### container-005

**Name:** Container images should use recent base images

Base images older than 90 days may contain unpatched vulnerabilities.
Regular base image updates ensure security patches are applied and
reduce the attack surface from accumulated CVEs.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 SI-2
- cis-docker 4.2

**Remediation:**
1. Check for newer versions of base image
2. Review base image changelog for security fixes
3. Update FROM instruction in Dockerfile
4. Test application compatibility
5. Rebuild and deploy updated image
6. Consider automated base image update pipelines


### container-008

**Name:** Container images should not use latest tag

The 'latest' tag is mutable and can change unexpectedly.
Using specific version tags or digests ensures reproducibility
and prevents unexpected changes to running workloads.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 CM-2
- cis-docker 4.7
- cis-kubernetes 5.5.1

**Remediation:**
1. Identify current image tag
2. Replace 'latest' with specific version tag
3. Better yet, use image digest (sha256:...)
4. Update Kubernetes manifests and Dockerfiles
5. Implement CI/CD rules to prevent latest tag usage
6. Use admission controllers to enforce this policy


## Low Severity

### container-011

**Name:** Container images should have SBOM available

Software Bill of Materials (SBOM) provides a complete inventory
of components in a container image. SBOMs enable rapid vulnerability
response and supply chain transparency.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 CM-8
- slsa Provenance
- eo-14028 4(e)

**Remediation:**
1. Generate SBOM during image build
2. Use Syft, Trivy, or similar SBOM tools
3. Choose SBOM format: SPDX, CycloneDX, or SWID
4. Attach SBOM to image as attestation
5. Store SBOM in registry or artifact store
6. Include SBOM generation in CI/CD pipeline


### container-012

**Name:** Container images should use minimal base images

Minimal base images like distroless, scratch, or Alpine reduce attack
surface by removing unnecessary packages, shells, and utilities.
Fewer components mean fewer potential vulnerabilities.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 CM-7
- cis-docker 4.3

**Remediation:**
1. Review current base image size and packages
2. Consider switching to minimal images:
   - gcr.io/distroless/* for production
   - alpine:* for smaller images
   - scratch for static binaries
3. Use multi-stage builds to minimize final image
4. Remove unnecessary packages and files
5. Test application functionality with minimal base
6. Document any required additional packages


### container-015

**Name:** Container images should not contain high-risk licenses

Software licenses in container images can create legal and compliance
risks. Certain licenses (GPL, AGPL) may require source disclosure.
Images should be audited for license compatibility.


**Resource Type:** `container_image`

**Compliance:**
- nist-800-53 SA-4
- iso-27001 A.5.32

**Remediation:**
1. Generate SBOM with license information
2. Review licenses for compatibility
3. Identify copyleft or restrictive licenses
4. Consult legal for compliance requirements
5. Replace components with incompatible licenses
6. Document license obligations

