# K8S Policies

Security policies for K8S resources.

## Critical Severity

### k8s-pod-001

**Name:** Containers should not run privileged

Privileged containers have access to all host capabilities and
can potentially compromise the node. Containers should not run
in privileged mode unless absolutely necessary.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.1
- nist-800-53 AC-6
- pci-dss 7.1

**Remediation:**
1. Review the pod specification
2. Locate containers with privileged: true
3. Remove the privileged setting or set to false
4. Consider using specific capabilities instead
5. If privileged access is required, document the exception
6. Apply the updated pod specification


### k8s-rbac-001

**Name:** Cluster-admin role should not be widely used

The cluster-admin role provides full access to all resources
in all namespaces. Bindings to this role should be limited
to essential administrators only.


**Resource Type:** `k8s_cluster_role_binding`

**Compliance:**
- cis-kubernetes 5.1.1
- nist-800-53 AC-6
- pci-dss 7.1

**Remediation:**
1. Review the cluster role binding
2. Identify all subjects with cluster-admin access
3. Create specific roles with minimal required permissions
4. Migrate users to appropriate roles
5. Remove unnecessary cluster-admin bindings
6. Document remaining cluster-admin users


### k8s-rbac-004

**Name:** Roles with pod exec access should be limited

The ability to exec into pods allows running arbitrary
commands inside containers, potentially compromising
applications and accessing sensitive data.


**Resource Type:** `k8s_cluster_role`

**Compliance:**
- cis-kubernetes 5.1.4
- nist-800-53 AC-6

**Remediation:**
1. Review the role definition
2. Identify rules granting pods/exec access
3. Remove pods/exec unless absolutely necessary
4. Limit to specific namespaces or pods
5. Implement audit logging for exec commands
6. Consider using debugging tools instead


### k8s-rbac-005

**Name:** Roles with node/proxy access should be limited

The ability to proxy to nodes allows accessing the kubelet API,
which can be used to execute commands on nodes, access logs, and
potentially escalate privileges.


**Resource Type:** `k8s_cluster_role`

**Compliance:**
- cis-kubernetes 5.1.5
- nist-800-53 AC-6

**Remediation:**
1. Review the role definition
2. Identify rules granting nodes/proxy access
3. Remove nodes/proxy unless absolutely necessary
4. Use more specific access patterns if possible
5. Implement audit logging for node access
6. Consider using dedicated monitoring tools instead


### k8s-rbac-006

**Name:** Roles with impersonation access should be limited

The ability to impersonate users, groups, or service accounts allows
bypassing RBAC controls by acting as other identities. This is a
powerful privilege that should be strictly limited.


**Resource Type:** `k8s_cluster_role`

**Compliance:**
- cis-kubernetes 5.1.6
- nist-800-53 AC-6

**Remediation:**
1. Review the role definition
2. Identify rules granting impersonate verb
3. Remove impersonation unless absolutely necessary
4. Limit impersonation to specific resources if needed
5. Implement audit logging for impersonation actions
6. Review all bindings to this role


### k8s-rbac-007

**Name:** Roles with certificate signing access should be limited

Access to approve or sign certificate signing requests can be used
to issue certificates for arbitrary identities, potentially gaining
unauthorized access to the cluster.


**Resource Type:** `k8s_cluster_role`

**Compliance:**
- cis-kubernetes 5.1.7
- nist-800-53 AC-6

**Remediation:**
1. Review the role definition
2. Identify rules granting CSR approval access
3. Remove CSR access unless absolutely necessary
4. Limit CSR signers to specific certificate types
5. Implement audit logging for CSR approvals
6. Use automated certificate management (cert-manager)


## High Severity

### k8s-net-003

**Name:** Ingress resources should have TLS enabled

Ingress resources expose applications to external traffic. All ingress
resources should have TLS configured to encrypt traffic in transit and
prevent man-in-the-middle attacks.


**Resource Type:** `k8s_ingress`

**Compliance:**
- cis-kubernetes 5.4.1
- nist-800-53 SC-8
- pci-dss 4.2.1

**Remediation:**
1. Generate or obtain a TLS certificate for the ingress hosts
2. Create a Kubernetes secret with the certificate:
   kubectl create secret tls my-tls-secret \
     --cert=path/to/cert.crt \
     --key=path/to/cert.key
3. Add TLS configuration to the Ingress:
   spec:
     tls:
     - hosts:
       - example.com
       secretName: my-tls-secret
4. Consider using cert-manager for automated certificate management


### k8s-net-005

**Name:** Network policies should not allow traffic from all sources

Network policies that allow traffic from all pods or all namespaces
provide insufficient isolation. Policies should be specific about
allowed sources to maintain proper network segmentation.


**Resource Type:** `k8s_network_policy`

**Compliance:**
- cis-kubernetes 5.3.2
- nist-800-53 SC-7

**Remediation:**
1. Review the NetworkPolicy ingress rules
2. Replace overly permissive selectors with specific ones:
   - Replace empty podSelector with specific labels
   - Replace empty namespaceSelector with specific namespaces
3. Use IP blocks only when necessary and be specific
4. Example of a specific ingress rule:
   ingress:
   - from:
     - podSelector:
         matchLabels:
           app: frontend
     - namespaceSelector:
         matchLabels:
           name: production
5. Test connectivity after changes


### k8s-pod-002

**Name:** Pods should not use host networking

Using host networking allows the pod to access all network
interfaces on the node, bypassing network policies and
exposing sensitive network traffic. This should be avoided.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.4
- nist-800-53 SC-7

**Remediation:**
1. Review the pod specification
2. Locate hostNetwork: true setting
3. Remove hostNetwork or set to false
4. Use Kubernetes Services for network connectivity
5. Apply the updated pod specification


### k8s-pod-003

**Name:** Pods should not share host PID namespace

Sharing the host PID namespace allows containers to see
all processes on the host, potentially exposing sensitive
information and enabling container escape attacks.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.2
- nist-800-53 SC-39

**Remediation:**
1. Review the pod specification
2. Locate hostPID: true setting
3. Remove hostPID or set to false
4. If process visibility is needed, use sidecar containers
5. Apply the updated pod specification


### k8s-pod-004

**Name:** Pods should not share host IPC namespace

Sharing the host IPC namespace allows containers to access
inter-process communication resources on the host, potentially
enabling attacks through shared memory.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.3
- nist-800-53 SC-39

**Remediation:**
1. Review the pod specification
2. Locate hostIPC: true setting
3. Remove hostIPC or set to false
4. Use Kubernetes-native communication patterns
5. Apply the updated pod specification


### k8s-pod-005

**Name:** Containers should run as non-root user

Running containers as root increases the attack surface
and potential damage from a container escape. Containers
should run as a non-root user whenever possible.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.6
- nist-800-53 AC-6
- pci-dss 7.1

**Remediation:**
1. Review the pod specification
2. Add securityContext at the pod level
3. Set runAsNonRoot: true
4. Optionally specify a runAsUser (non-zero)
5. Ensure the container image supports non-root execution
6. Apply the updated pod specification


### k8s-pod-007

**Name:** Containers should not allow privilege escalation

Privilege escalation allows a process to gain more privileges
than its parent. Disabling this prevents container escape
and lateral movement attacks.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.5
- nist-800-53 AC-6

**Remediation:**
1. Review the pod specification
2. For each container, add securityContext
3. Set allowPrivilegeEscalation: false
4. Test the application functionality
5. Apply the updated pod specification


### k8s-pod-009

**Name:** Pods should not mount host path volumes

Mounting host paths allows containers to access the host
filesystem, potentially exposing sensitive data or enabling
container escape attacks.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.9
- nist-800-53 SC-28

**Remediation:**
1. Review the pod specification
2. Identify volumes with hostPath type
3. Replace hostPath with alternative volume types:
   - emptyDir for temporary storage
   - persistentVolumeClaim for persistent data
   - configMap or secret for configuration
4. If hostPath is required, use Pod Security Admission
5. Apply the updated pod specification


### k8s-rbac-002

**Name:** Roles should not use wildcard permissions

Wildcard (*) permissions grant access to all resources or
all verbs, violating the principle of least privilege.
Roles should explicitly specify required permissions.


**Resource Type:** `k8s_cluster_role`

**Compliance:**
- cis-kubernetes 5.1.3
- nist-800-53 AC-6

**Remediation:**
1. Review the cluster role definition
2. Identify rules with "*" in resources or verbs
3. Replace wildcards with specific resources and verbs
4. Test with the reduced permissions
5. Update the role definition
6. Document the required permissions


### k8s-rbac-003

**Name:** Roles with secrets access should be limited

Access to secrets allows reading sensitive information like
passwords, API keys, and certificates. Roles with secrets
access should be carefully reviewed and limited.


**Resource Type:** `k8s_cluster_role`

**Compliance:**
- cis-kubernetes 5.1.2
- nist-800-53 AC-6
- pci-dss 3.4

**Remediation:**
1. Review the role definition
2. Identify rules granting secrets access
3. Evaluate if secrets access is necessary
4. Use external secrets management if possible
5. Limit secrets access to specific namespaces
6. Audit secrets access regularly


### k8s-rbac-007

**Name:** Roles should not be overly permissive

Roles with a high risk score indicate excessive permissions
that violate the principle of least privilege. Review and
reduce permissions to the minimum required.


**Resource Type:** `k8s_cluster_role`

**Compliance:**
- cis-kubernetes 5.1.3
- nist-800-53 AC-6

**Remediation:**
1. Review the role's permission rules
2. Identify overly broad permissions
3. Replace wildcards with specific resources
4. Limit verbs to required actions only
5. Split into multiple specific roles if needed
6. Test workloads with reduced permissions


## Medium Severity

### k8s-net-001

**Name:** Namespaces should have default deny ingress network policy

A default deny ingress network policy ensures that all pods in a namespace
are isolated by default, only allowing explicitly permitted traffic.
Without this, pods can receive traffic from any source.


**Resource Type:** `k8s_namespace`

**Compliance:**
- cis-kubernetes 5.3.2
- nist-800-53 SC-7

**Remediation:**
1. Create a default deny ingress NetworkPolicy for the namespace:
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny-ingress
   spec:
     podSelector: {}
     policyTypes:
     - Ingress
2. Apply the policy to the namespace
3. Create explicit allow policies for required traffic
4. Test connectivity to ensure applications work correctly


### k8s-net-002

**Name:** Namespaces should have default deny egress network policy

A default deny egress network policy ensures that all pods in a namespace
cannot initiate outbound connections by default. This prevents data
exfiltration and limits the blast radius of compromised pods.


**Resource Type:** `k8s_namespace`

**Compliance:**
- cis-kubernetes 5.3.2
- nist-800-53 SC-7

**Remediation:**
1. Create a default deny egress NetworkPolicy for the namespace:
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny-egress
   spec:
     podSelector: {}
     policyTypes:
     - Egress
2. Apply the policy to the namespace
3. Create explicit allow policies for required outbound traffic
4. Ensure DNS access is allowed if pods need name resolution


### k8s-net-006

**Name:** Namespaces should have resource quotas defined

Resource quotas prevent a single namespace from consuming excessive
cluster resources. Without quotas, a misbehaving or compromised
workload could cause a denial of service affecting other tenants.


**Resource Type:** `k8s_namespace`

**Compliance:**
- cis-kubernetes 5.2.1
- nist-800-53 SC-5

**Remediation:**
1. Determine appropriate resource limits for the namespace
2. Create a ResourceQuota:
   apiVersion: v1
   kind: ResourceQuota
   metadata:
     name: compute-quota
   spec:
     hard:
       requests.cpu: "4"
       requests.memory: 8Gi
       limits.cpu: "8"
       limits.memory: 16Gi
       pods: "20"
3. Apply the quota to the namespace
4. Monitor quota usage and adjust as needed


### k8s-net-009

**Name:** Network policies should specify ports for ingress rules

Network policies with ingress rules should specify which ports are
allowed. Policies without port restrictions allow traffic on all ports,
which may be more permissive than intended.


**Resource Type:** `k8s_network_policy`

**Compliance:**
- cis-kubernetes 5.3.2
- nist-800-53 SC-7

**Remediation:**
1. Review the NetworkPolicy ingress rules
2. Add port specifications to each rule:
   ingress:
   - from:
     - podSelector:
         matchLabels:
           role: frontend
     ports:
     - protocol: TCP
       port: 80
     - protocol: TCP
       port: 443
3. Only allow the specific ports required by the application
4. Test connectivity after making changes


### k8s-net-010

**Name:** Ingress resources should specify hosts

Ingress resources should define specific hosts rather than accepting
traffic for any host. Wildcard or missing host specifications can
lead to unintended exposure of services.


**Resource Type:** `k8s_ingress`

**Compliance:**
- nist-800-53 AC-3
- cis-kubernetes 5.4.1

**Remediation:**
1. Review the Ingress configuration
2. Add specific hosts to each rule:
   spec:
     rules:
     - host: api.example.com
       http:
         paths:
         - path: /
           pathType: Prefix
           backend:
             service:
               name: api-service
               port:
                 number: 80
3. Ensure TLS configuration also references the same hosts
4. Avoid using wildcard hosts when possible
5. Update DNS records to point to the ingress controller


### k8s-pod-006

**Name:** Container root filesystem should be read-only

A read-only root filesystem prevents attackers from modifying
the container's filesystem, reducing the attack surface.
Write operations should use mounted volumes instead.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.8
- nist-800-53 CM-7

**Remediation:**
1. Review the pod specification
2. For each container, add securityContext
3. Set readOnlyRootFilesystem: true
4. Mount writable volumes for required write paths
5. Test the application with read-only filesystem
6. Apply the updated pod specification


### k8s-pod-008

**Name:** Container capabilities should be dropped

Linux capabilities give containers fine-grained privileges.
All capabilities should be dropped by default, and only
required capabilities should be explicitly added.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.2.7
- nist-800-53 AC-6
- pci-dss 7.1

**Remediation:**
1. Review the pod specification
2. For each container, add securityContext.capabilities
3. Set drop: ["ALL"] to drop all capabilities
4. Add only required capabilities back with 'add'
5. Test the application with reduced capabilities
6. Apply the updated pod specification


### k8s-pod-010

**Name:** Containers should have resource limits defined

Resource limits prevent containers from consuming excessive
CPU and memory, protecting against denial of service attacks
and ensuring fair resource allocation.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.4.1
- nist-800-53 SC-6

**Remediation:**
1. Review the pod specification
2. For each container, add resources.limits
3. Set appropriate CPU and memory limits
4. Consider setting requests equal to limits
5. Test under load to validate limits
6. Apply the updated pod specification


### k8s-pod-011

**Name:** Container images should not use latest tag

Using the 'latest' tag for container images makes deployments
unpredictable and can lead to unexpected changes. Use specific
image versions or digests for reproducibility.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.5.1
- nist-800-53 CM-2

**Remediation:**
1. Review the pod specification
2. Identify containers using :latest tag
3. Replace with specific version tags
4. Consider using image digests for immutability
5. Implement image scanning in CI/CD pipeline
6. Apply the updated pod specification


### k8s-pod-014

**Name:** Pods should have seccomp profile configured

Seccomp (secure computing mode) limits the system calls that containers
can make, reducing the attack surface. Without a seccomp profile,
containers can use any system call.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.7.2
- nist-800-53 SC-7

**Remediation:**
1. Review the pod specification
2. Add a seccomp profile to the security context:
   spec:
     securityContext:
       seccompProfile:
         type: RuntimeDefault
3. For stricter control, use type: Localhost with a custom profile
4. Test the application with the profile enabled
5. Monitor for seccomp violations


### k8s-pod-016

**Name:** Pods should disable automatic service account token mounting

By default, pods mount a service account token that can be used to
authenticate to the Kubernetes API. Most pods don't need this access,
and the token should be disabled to reduce exposure.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.1.6
- nist-800-53 AC-6

**Remediation:**
1. Review if the pod needs Kubernetes API access
2. If not needed, disable automount in the pod spec:
   spec:
     automountServiceAccountToken: false
3. Or disable on the service account:
   automountServiceAccountToken: false
4. If API access is needed, use specific RBAC permissions
5. Consider using projected service account tokens


### k8s-pod-019

**Name:** Containers should have memory requests defined

Memory requests help the scheduler make better placement decisions
and ensure pods have the resources they need. Without requests,
pods may be scheduled on nodes without sufficient memory.


**Resource Type:** `k8s_pod`

**Compliance:**
- nist-800-53 SC-5
- cis-kubernetes 5.4.1

**Remediation:**
1. Review container memory requirements
2. Add memory requests to each container:
   containers:
   - name: app
     resources:
       requests:
         memory: "128Mi"
3. Set requests based on typical usage
4. Consider setting limits as well
5. Monitor actual usage and adjust requests


### k8s-pod-020

**Name:** Containers should have CPU requests defined

CPU requests help the scheduler make better placement decisions
and ensure fair CPU allocation. Without requests, pods may
starve other workloads or be scheduled on overloaded nodes.


**Resource Type:** `k8s_pod`

**Compliance:**
- nist-800-53 SC-5
- cis-kubernetes 5.4.1

**Remediation:**
1. Review container CPU requirements
2. Add CPU requests to each container:
   containers:
   - name: app
     resources:
       requests:
         cpu: "100m"
3. Set requests based on typical usage
4. Consider setting limits to prevent CPU hogging
5. Monitor actual usage and adjust requests


### k8s-rbac-005

**Name:** Service account token auto-mount should be disabled

Automatically mounting service account tokens in pods gives
all containers access to the Kubernetes API. This should
be disabled unless the pod needs to interact with the API.


**Resource Type:** `k8s_service_account`

**Compliance:**
- cis-kubernetes 5.1.6
- nist-800-53 AC-6

**Remediation:**
1. Review the service account
2. Set automountServiceAccountToken: false
3. For pods that need API access, explicitly set it
4. Use workload identity where available
5. Apply the updated service account


### k8s-rbac-006

**Name:** Default service account should not be used for workloads

The default service account in each namespace should not be
used for application workloads. Create dedicated service
accounts with minimal permissions instead.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.1.5
- nist-800-53 AC-6

**Remediation:**
1. Create a dedicated service account for the workload
2. Grant only required permissions to the service account
3. Update the pod spec to use the new service account
4. Disable token automount if API access is not needed
5. Apply the updated configuration


### k8s-wl-001

**Name:** Deployments should have multiple replicas for high availability

Running a single replica provides no redundancy. Production deployments
should have at least 2 replicas to ensure high availability and
prevent downtime during updates or node failures.


**Resource Type:** `k8s_deployment`

**Compliance:**
- nist-800-53 CP-10
- soc2 A1.2

**Remediation:**
1. Review the deployment specification
2. Increase the replica count to at least 2:
   spec:
     replicas: 2
3. Ensure pod anti-affinity is configured to spread pods
4. Consider using pod disruption budgets
5. Verify readiness probes are configured


### k8s-wl-003

**Name:** StatefulSets should use PersistentVolumeClaims

StatefulSets are designed for stateful applications that require
persistent storage. Using emptyDir or hostPath volumes loses data
when pods are rescheduled.


**Resource Type:** `k8s_statefulset`

**Compliance:**
- nist-800-53 CP-9

**Remediation:**
1. Review the StatefulSet specification
2. Add volumeClaimTemplates for persistent storage:
   spec:
     volumeClaimTemplates:
     - metadata:
         name: data
       spec:
         accessModes: ["ReadWriteOnce"]
         storageClassName: "standard"
         resources:
           requests:
             storage: 10Gi
3. Mount the volume in the container
4. Verify backup procedures for the persistent data


### k8s-wl-009

**Name:** Services should have pod selectors defined

Services without selectors don't automatically route traffic to pods.
This is only valid for external services or when using Endpoints
directly. Most services should have selectors to match pods.


**Resource Type:** `k8s_service`

**Compliance:**
- nist-800-53 CM-6

**Remediation:**
1. Review the Service specification
2. Add a selector to match target pods:
   spec:
     selector:
       app: my-app
       tier: frontend
3. Ensure pods have matching labels
4. Verify connectivity after changes
5. If intentionally selector-less, document the reason


### k8s-wl-010

**Name:** Container images should use digest references

Using image digests instead of tags ensures immutability and
reproducibility. Tags like 'latest' or version tags can change,
leading to unexpected behavior or security vulnerabilities.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.5.1
- nist-800-53 CM-2

**Remediation:**
1. Review the pod/deployment container images
2. Replace tags with digests:
   containers:
   - name: app
     image: myregistry.io/app@sha256:abc123...
3. Use CI/CD to automatically resolve and pin digests
4. Consider using admission controllers to enforce this
5. Keep a record of digest to version mappings


## Low Severity

### k8s-net-004

**Name:** Ingress resources should not use default backends

Default backends in Ingress resources act as catch-all routes that
can inadvertently expose services. Explicitly defining rules for
each path is more secure and reduces attack surface.


**Resource Type:** `k8s_ingress`

**Compliance:**
- nist-800-53 AC-3

**Remediation:**
1. Review the Ingress configuration
2. Remove the defaultBackend specification
3. Define explicit rules for each path that needs routing:
   spec:
     rules:
     - host: example.com
       http:
         paths:
         - path: /api
           pathType: Prefix
           backend:
             service:
               name: api-service
               port:
                 number: 80
4. Consider using a 404 service for unmatched routes


### k8s-net-007

**Name:** Namespaces should have limit ranges defined

Limit ranges set default resource requests and limits for pods that
don't specify them. This prevents pods from running without resource
constraints and ensures fair resource distribution.


**Resource Type:** `k8s_namespace`

**Compliance:**
- cis-kubernetes 5.2.1
- nist-800-53 SC-5

**Remediation:**
1. Create a LimitRange for the namespace:
   apiVersion: v1
   kind: LimitRange
   metadata:
     name: default-limits
   spec:
     limits:
     - default:
         cpu: "500m"
         memory: "512Mi"
       defaultRequest:
         cpu: "100m"
         memory: "128Mi"
       max:
         cpu: "2"
         memory: "4Gi"
       min:
         cpu: "50m"
         memory: "64Mi"
       type: Container
2. Apply the LimitRange to the namespace
3. Existing pods won't be affected; only new pods will get defaults


### k8s-net-008

**Name:** Secrets should use appropriate secret types

Kubernetes secrets should use the correct type for their content.
Using Opaque type for TLS certificates or Docker configs may indicate
misconfiguration or bypass of built-in validation.


**Resource Type:** `k8s_secret`

**Compliance:**
- nist-800-53 CM-6

**Remediation:**
1. Review the secret content and determine the correct type:
   - kubernetes.io/tls for TLS certificates
   - kubernetes.io/dockerconfigjson for Docker registry credentials
   - kubernetes.io/basic-auth for basic authentication
   - kubernetes.io/ssh-auth for SSH credentials
2. Recreate the secret with the appropriate type:
   kubectl create secret tls my-tls-secret \
     --cert=path/to/tls.crt \
     --key=path/to/tls.key
3. Update workloads to reference the new secret
4. Delete the old improperly typed secret


### k8s-pod-012

**Name:** Containers should have liveness probes defined

Liveness probes help Kubernetes detect and restart unhealthy
containers. Without probes, containers may become unresponsive
but continue running, impacting service availability.


**Resource Type:** `k8s_pod`

**Compliance:**
- nist-800-53 SC-5

**Remediation:**
1. Review the pod specification
2. Add livenessProbe to each container
3. Configure appropriate health check endpoints
4. Set suitable initialDelaySeconds and periodSeconds
5. Test that the probe correctly detects failures
6. Apply the updated pod specification


### k8s-pod-013

**Name:** Containers should have readiness probes defined

Readiness probes help Kubernetes determine when a container is ready
to accept traffic. Without probes, traffic may be sent to containers
that are not fully initialized, causing request failures.


**Resource Type:** `k8s_pod`

**Compliance:**
- nist-800-53 SC-5

**Remediation:**
1. Review the pod specification
2. Add readinessProbe to each container
3. Configure appropriate health check endpoints
4. Set suitable initialDelaySeconds and periodSeconds
5. Ensure probe correctly indicates readiness state
6. Apply the updated pod specification


### k8s-pod-015

**Name:** Pods should have AppArmor profile configured

AppArmor provides mandatory access control for containers, limiting
their access to host resources. Without an AppArmor profile,
containers rely only on DAC for security.


**Resource Type:** `k8s_pod`

**Compliance:**
- cis-kubernetes 5.7.3
- nist-800-53 AC-3

**Remediation:**
1. Ensure AppArmor is enabled on cluster nodes
2. Add AppArmor annotation to the pod:
   metadata:
     annotations:
       container.apparmor.security.beta.kubernetes.io/container-name: runtime/default
3. For custom profiles, use localhost/profile-name
4. Test application compatibility with the profile
5. Monitor for AppArmor denials


### k8s-pod-017

**Name:** Containers should have startup probes for slow-starting apps

Startup probes prevent liveness probe failures during application
startup. Without startup probes, slow-starting containers may be
killed by liveness probes before they're ready.


**Resource Type:** `k8s_pod`

**Compliance:**
- nist-800-53 SC-5

**Remediation:**
1. Review container startup time requirements
2. Add startupProbe to containers that need it:
   containers:
   - name: app
     startupProbe:
       httpGet:
         path: /healthz
         port: 8080
       failureThreshold: 30
       periodSeconds: 10
3. Tune failureThreshold and periodSeconds for your app
4. Startup probe runs before liveness probe takes over
5. Test startup behavior under various conditions


### k8s-pod-018

**Name:** Containers should use Always or IfNotPresent image pull policy

Image pull policy controls when images are pulled from registries.
Using Never for non-local images may result in running outdated
or compromised images if the node cache is stale.


**Resource Type:** `k8s_pod`

**Compliance:**
- nist-800-53 CM-2

**Remediation:**
1. Review the container image pull policy
2. Set imagePullPolicy to Always or IfNotPresent:
   containers:
   - name: app
     image: myregistry.io/app:v1.0.0
     imagePullPolicy: Always
3. Use Always for mutable tags like latest
4. IfNotPresent is acceptable for immutable tags/digests
5. Configure imagePullSecrets for private registries


### k8s-wl-002

**Name:** Deployments should use RollingUpdate strategy

The RollingUpdate strategy ensures zero-downtime deployments by
gradually replacing old pods with new ones. Recreate strategy
causes downtime as all pods are terminated before new ones start.


**Resource Type:** `k8s_deployment`

**Compliance:**
- nist-800-53 CP-10

**Remediation:**
1. Review the deployment specification
2. Set the strategy type to RollingUpdate:
   spec:
     strategy:
       type: RollingUpdate
       rollingUpdate:
         maxSurge: 25%
         maxUnavailable: 25%
3. Configure appropriate maxSurge and maxUnavailable values
4. Ensure readiness probes are configured for proper rollouts


### k8s-wl-004

**Name:** Jobs should have a backoff limit defined

Jobs without a backoff limit will retry indefinitely on failure,
potentially consuming resources and creating excessive pods.
A reasonable backoff limit ensures failed jobs eventually stop.


**Resource Type:** `k8s_job`

**Compliance:**
- nist-800-53 SC-5

**Remediation:**
1. Review the Job specification
2. Add a backoffLimit to control retries:
   spec:
     backoffLimit: 4
3. Consider the nature of the job when setting the limit
4. For critical jobs, consider alerting on failures
5. Review job history and adjust limit based on failure patterns


### k8s-wl-005

**Name:** Jobs should have TTL for automatic cleanup

Completed and failed jobs remain in the cluster consuming resources.
Setting ttlSecondsAfterFinished enables automatic cleanup of finished
jobs, preventing resource accumulation.


**Resource Type:** `k8s_job`

**Compliance:**
- nist-800-53 CM-7

**Remediation:**
1. Review the Job specification
2. Add ttlSecondsAfterFinished for automatic cleanup:
   spec:
     ttlSecondsAfterFinished: 86400
3. Choose a TTL that allows for log collection and debugging
4. Consider using CronJobs with history limits instead
5. Monitor job history to adjust TTL as needed


### k8s-wl-006

**Name:** CronJobs should have history limits configured

CronJobs without history limits can accumulate many completed jobs,
consuming cluster resources. Setting successfulJobsHistoryLimit and
failedJobsHistoryLimit controls how many completed jobs are retained.


**Resource Type:** `k8s_cronjob`

**Compliance:**
- nist-800-53 CM-7

**Remediation:**
1. Review the CronJob specification
2. Add history limits:
   spec:
     successfulJobsHistoryLimit: 3
     failedJobsHistoryLimit: 1
3. Balance between debugging needs and resource usage
4. Consider external log aggregation for job history
5. Monitor CronJob execution patterns


### k8s-wl-007

**Name:** CronJobs should have concurrency policy defined

Without a concurrency policy, CronJobs may allow multiple jobs to run
simultaneously, which can cause resource contention or data corruption.
Defining a policy ensures predictable job execution.


**Resource Type:** `k8s_cronjob`

**Compliance:**
- nist-800-53 CM-6

**Remediation:**
1. Review the CronJob specification
2. Add a concurrency policy:
   spec:
     concurrencyPolicy: Forbid  # or Allow or Replace
3. Choose based on job requirements:
   - Forbid: Skip new job if previous is still running
   - Replace: Replace previous job with new one
   - Allow: Allow concurrent execution
4. Forbid is safest for most use cases


### k8s-wl-008

**Name:** DaemonSets should use RollingUpdate strategy

The RollingUpdate strategy for DaemonSets ensures pods are updated
one node at a time, minimizing impact. OnDelete strategy requires
manual pod deletion for updates, which is error-prone.


**Resource Type:** `k8s_daemonset`

**Compliance:**
- nist-800-53 CM-3

**Remediation:**
1. Review the DaemonSet specification
2. Set the update strategy to RollingUpdate:
   spec:
     updateStrategy:
       type: RollingUpdate
       rollingUpdate:
         maxUnavailable: 1
3. Configure maxUnavailable based on cluster size
4. Ensure readiness probes are configured
5. Test rollouts in non-production first

