package GCP

deny{
 not (gcp_security_bigquery_no_public_access)
 not (gcp_security_iam_no_folder_level_default_service_account_assignment)
 not (gcp_security_iam_no_folder_level_service_account_impersonation)
 not (gcp_security_iam_no_privileged_service_accounts)
 not (gcp_security_storage_enable_ubla)
 not (gcp_security_storage_no_public_access)
 not (gcp_security_compute_disk_encryption_customer_key)
 not (gcp_security_compute_disk_encryption_required)
 not (gcp_security_compute_enable_shielded_vm)
 not (gcp_security_compute_enable_vpc_flow_logs)
 not (gcp_security_compute_no_default_service_account)
 not (gcp_security_compute_no_ip_forwarding)
 not (gcp_security_compute_no_plaintext_vm_disk_keys)
 not (gcp_security_compute_no_public_ip)
 not (gcp_security_dns_enable_dnssec)
 not (gcp_security_dns_enable_dnssec)
 not (gcp_security_gke_enable_auto_repair)
 not (gcp_security_gke_enable_auto_upgrade)
 not (gcp_security_gke_enable_ip_aliasing)
 not (gcp_security_gke_enable_master_networks)
 not (gcp_security_gke_enable_network_policy)
 not (gcp_security_gke_enable_private_cluster)
 not (gcp_security_gke_enable_stackdriver_logging)
 not (gcp_security_gke_enable_stackdriver_monitoring)
 not (gcp_security_gke_metadata_endpoints_disabled)
 not (gcp_security_gke_no_basic_authentication)
 not (gcp_security_gke_no_public_control_plane)
 not (gcp_security_gke_node_metadata_security)
 not (gcp_security_gke_node_pool_uses_cos)
 not (gcp_security_gke_node_shielding_enabled)
 not (gcp_security_gke_use_cluster_labels)
 not (gcp_security_gke_use_rbac_permissions)
}

# POLICY 1
# BigQuery datasets should only be accessible within the organization
# BigQuery datasets should not be configured to provide access to `allAuthenticatedUsers` as this provides any authenticated GCP user, even those outside of your organization, access to your BigQuery dataset. This can lead to exposure of sensitive data to the public internet.
gcp_security_bigquery_no_public_access[msg1]{
  input.resource.google_bigquery_dataset.dataset.access[_].special_group == "allAuthenticatedUsers"
  msg1 := "BigQuery datasets should not be configured to provide access to allAuthenticatedUsers"
 }

#POLICY 2
# Roles should not be assigned to default service accounts
# Default service accounts should not be used when granting access to folders as this can violate least privilege. It is recommended to use specialized service accounts instead.
gcp_security_iam_no_folder_level_default_service_account_assignment[msg2]{
   count(regex.find_n(`.+@appspot\.gserviceaccount\.com$`, input.resource.google_folder_iam_member[_].member, -1)) >0
   count(regex.find_n(`.+-compute@developer\.gserviceaccount\.com$`, input.resource.google_folder_iam_member[_].member, -1)) >0
   count(regex.find_n(`data\.google_compute_default_service_account`, input.resource.google_folder_iam_member[_].member, -1)) >0
   msg2 := "Roles should not be assigned to default service accounts"
 }

#POLICY 3
# Users should not be granted service account access at the folder level
# Users with service account access at the folder level can impersonate any service account. Instead, they should be given access to particular service accounts as required.
gcp_security_iam_no_folder_level_service_account_impersonation[msg3]{
   count(regex.find_n(`iam\.serviceAccountUser`, input.resource.google_folder_iam_binding[_].role, -1)) >0
   msg3 := "Users should not be granted service account access at the folder level"
 }

 # POLICY 4
# Service accounts should not have roles assigned with excessive privileges
# Service accounts should have a minimal set of permissions assigned to accomplish their job. They should never have excessive access because if compromised, an attacker can escalate privileges and take over the entire account.
gcp_security_iam_no_privileged_service_accounts{
  role_owner_editor 
 }

 role_owner_editor[msg4]{
 count(regex.find_n(`roles\/owner`, input.resource.google_project_iam_member[_].role, -1)) >0
 msg4 := "Service accounts should not have roles assigned with excessive privileges - Role Owner"
 }

  role_owner_editor[msg4]{
 count(regex.find_n(`roles\/editor`, input.resource.google_project_iam_member[_].role, -1)) >0
 msg4 := "Service accounts should not have roles assigned with excessive privileges - Role Editor"
 }

# POLICY 5
# Ensure that Cloud Storage buckets have uniform bucket-level access enabled
# Google Cloud Storage buckets should be configured with uniform bucket-level access.
gcp_security_storage_enable_ubla[msg5]{
  input.resource.google_storage_bucket[_].uniform_bucket_level_access == false
  msg5 := "Ensure that Cloud Storage buckets have uniform bucket-level access enabled"
 }

# POLICY 6
# Ensure that Cloud Storage bucket is not publicly accessible
#  Google Cloud Storage buckets that define 'allUsers' or 'allAuthenticatedUsers' as members in an IAM member/binding causes data to be exposed outside of the organization. This can lead to exposure of sensitive data. The recommended approach is to restrict public access.
gcp_security_storage_no_public_access{
 public_access 
 }
 
 public_access[msg6]{
  input.resource.google_storage_bucket_iam_binding[_].members[_] == "allAuthenticatedUsers" 
  msg6 := "allAuthenticatedUsers - Ensure that Cloud Storage bucket is not publicly accessible"
 }
 
 public_access[msg6]{
  input.resource.google_storage_bucket_iam_binding[_].members[_] == "allUsers"
  msg6 := "allUsers -Ensure that Cloud Storage bucket is not publicly accessible"
 }

 # POLICY 7
# Disks should be encrypted with Customer Supplied Encryption Keys
# Google Cloud compute instances should use disk encryption using a customer-supplied encryption key. If you do not provide an encryption key when creating the disk, then the disk will be encrypted using an automatically generated key, and you do not need to provide the key to use the disk later.

gcp_security_compute_disk_encryption_customer_key[msg7]{
    disk := input.resource.google_compute_disk[_]
    not disk.disk_encryption_key
    msg7 := "disk_encryption_key block is missing"
} 

gcp_security_compute_disk_encryption_customer_key[msg7]{ 
    disk := input.resource.google_compute_disk[_]
    disk_encryption_key := disk.disk_encryption_key
    disk_encryption_key != null
    disk_encryption_key.kms_key_self_link == ""
    msg7 := "The `disk_encryption_key` key is defined and the arguments must not be empty strings."
}

# POLICY 8
# Disk encryption Keys should not be passed as plaintext
# Google Cloud compute instances should use disk encryption using a customer-supplied encryption key. One of the options is for the `disk_encryption_key` is `raw_key`, which is the key in plaintext. \n\nSensitive values such as raw encryption keys should not be included in your Terraform code and should be stored securely by a secrets manager

gcp_security_compute_disk_encryption_required[msg8]{
    disk := input.resource.google_compute_disk[_]
    not disk.disk_encryption_key
    msg8 := "disk_encryption_key block is missing"
} 

gcp_security_compute_disk_encryption_required[msg8]{ 
    disk := input.resource.google_compute_disk[_]
    disk_encryption_key := disk.disk_encryption_key
    disk_encryption_key != null
    disk.disk_encryption_key.raw_key
  msg8 := "raw_key should not be used"
}

# POLICY 9
# Verify shielded VM is enabled on compute instances
# Shielded VMs are virtual machines (VMs) on Google Cloud hardened by a set of security controls that help defend against rootkits and bootkits. Using Shielded VMs helps protect enterprise workloads from threats like remote attacks, privilege escalation, and malicious insiders. Shielded VMs leverage advanced platform security capabilities such as secure and measured boot, a virtual trusted platform module (vTPM), UEFI firmware, and integrity monitoring.
# Check if the `shielded_instance_config` is configured on the instance, and if `enable_vtpm` and `enable_integrity_monitoring` are set to `false`
gcp_security_compute_enable_shielded_vm {
shielded_instance_config
 }
 
shielded_instance_config[msg9]{
  shielded_config := input.resource.google_compute_instance[_].shielded_instance_config
  shielded_config != ""
  shielded_config.enable_vtpm == false
  shielded_config.enable_integrity_monitoring == false
  msg9 := "If the `shielded_instance_config` is configured on the instance then `enable_vtpm` and `enable_integrity_monitoring` must be set to `true`"
 }
 
shielded_instance_config[msg9]{
 shielded_config := input.resource.google_compute_instance[_]
 not shielded_config.shielded_instance_config
 msg9 := "`shielded_instance_config` must be configured on the instance"
}

# POLICY 10
# Verify VPC flow logs enabled on compute instances
# VPC flow logs record information about all traffic, which is a vital tool in reviewing anomalous traffic. Google Compute Engine subnetworks that do not have VPC flow logs enabled have limited information for auditing and awareness.
# Google Compute Engine subnets configured as INTERNAL_HTTPS_LOAD_BALANCER do not support VPC flow logs. Compute subnetworks with `purpose INTERNAL_HTTPS_LOAD_BALANCER` attribute will not be evaluated.
gcp_security_compute_enable_vpc_flow_logs{
 INTERNAL_HTTPS_LOAD_BALANCER_log_config_check
 }

INTERNAL_HTTPS_LOAD_BALANCER_log_config_check[msg10]{
  input.resource.google_compute_subnetwork[_].purpose == "INTERNAL_HTTPS_LOAD_BALANCER"
  msg10 := "Google Compute Engine subnets configured as INTERNAL_HTTPS_LOAD_BALANCER do not support VPC flow logs"
 }
  
 INTERNAL_HTTPS_LOAD_BALANCER_log_config_check[msg10]{
  config = input.resource.google_compute_subnetwork[_]
  not config.log_config
  msg10 := "VPC flow logs enabled on compute instances must be enabled i.e log config must be present "
 }

# POLICY 11
# Compute instances should not use the default service account
#  The default service account has full project access. Provisioning instances using the default service account gives the instance full access to the project. Compute instances should instead be assigned the minimal access they need.
gcp_security_compute_no_default_service_account[msg11]{
   count(regex.find_n(`.+-compute@developer\.gserviceaccount\.com`, input.resource.google_compute_instance[_].service_account.email, -1)) >0
   msg11 := "Compute instances should not use the default service account"
 }

# POLICY 12
# Compute instances should be configured with IP forwarding
# Disabling IP forwarding ensures the instance can only receive packets addressed to the instance and can only send packets with a source address of the instance.\n\nThe attribute `can_ip_forward` is optional on `google_compute_instance` and defaults to `false`. Instances with `can_ip_forward = true` will fail. \n
gcp_security_compute_no_ip_forwarding[msg12]{
  input.resource.google_compute_instance[_].can_ip_forward != false 
  msg12 := "Compute instances should be configured with IP forwarding"
 }

# POLICY 13
# VM disk encryption keys should not be provided in plaintext
# Providing your encryption key in plaintext format means anyone with access to the source code also has access to the key.\n\nWhen encrypting a `boot_disk`, it is not recommended to use the `disk_encryption_key_raw` argument as this passes the key in plaintext, which is not secure. Consider using `kms_key_self_link` or a secrets manager instead.
gcp_security_compute_no_plaintext_vm_disk_keys[msg13]{
  disk_encryption =  input.resource.google_compute_instance[_]
  disk_encryption.disk_encryption_key_raw
  msg13 := "VM disk encryption keys should not be provided in plaintext"
 }


# POLICY 14
# Compute instances should not be publicly exposed to the internet
# Google Cloud compute instances that have a public IP address are exposed on the internet and are at risk to attack. 
gcp_security_compute_no_public_ip{
 check_access_config_present_empty
 }
 
check_access_config_present_empty[msg14]{
 access_config :=  input.resource.google_compute_instance[_]
 not access_config.network_interface.access_config
 msg14 := "access_config does not exists."
 }

check_access_config_present_empty[msg14]{
 input.resource.google_compute_instance[_].network_interface.access_config == {}
 msg14 := " Compute instances should not be publicly exposed to the internet, Check if the `access_config` is empty."
}

# POLICY 15
# Cloud DNS should use DNSSEC
# DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation. Unverified DNS responses could lead to man-in-the-middle attacks. 
gcp_security_dns_enable_dnssec[msg15]{
 input.resource.google_dns_managed_zone[_].dnssec_config.state == "off"
 msg15 := " Cloud DNS should use DNSSEC which will prevent MITM attacks"
 }
 
 
# POLICY 16
# Zone signing should not use RSA SHA1 -Datasource
# RSA SHA1 is a weaker algorithm than SHA2-based algorithms such as RSA SHA256/512.
gcp_security_dns_enable_dnssec[msg16]{
 input.data.google_dns_keys[_].key_signing_keys.algorithm == "rsasha1"
 msg16 := "Zone signing should not use RSA SHA1"
 }

# POLICY 17
# Kubernetes should have 'Automatic repair' enabled
# Automatic repair will monitor nodes and attempt repair when a node fails multiple subsequent health checks. Failing nodes will require manual repair.
gcp_security_gke_enable_auto_repair[msg17]{
 input.resource.google_container_node_pool[_].management.auto_repair == false
 msg17 := "Kubernetes should have 'Automatic repair' enabled"
 }

# POLICY 18
#Kubernetes should have 'Automatic upgrade' enabled
# Automatic updates keep nodes updated with the latest cluster master version.
gcp_security_gke_enable_auto_upgrade[msg18]{
 input.resource.google_container_node_pool[_].management.auto_upgrade  == false
 msg18 := "Kubernetes should have 'Automatic upgrade' enabled"
 }
 
# POLICY 19
# Clusters should have IP aliasing enabled
# IP aliasing allows the reuse of public IPs internally, removing the need for a NAT gateway.
gcp_security_gke_enable_ip_aliasing[msg19]{
 ip_allocation = input.resource.google_container_cluster[_]
 not ip_allocation.ip_allocation_policy
 msg19 := "Clusters should have IP aliasing enabled"
 }
 
# POLICY 20
# Master authorized networks should be configured on GKE clusters
# Enabling authorized networks means you can restrict master access to a fixed set of CIDR ranges.
gcp_security_gke_enable_master_networks[msg20]{
 gke_cluster = input.resource.google_container_cluster[_]
 not gke_cluster.master_authorized_networks_config
 msg20 := "Master authorized networks should be configured on GKE clusters"
 }
 
# POLICY 21
# Network Policy should be enabled on GKE clusters
# Enabling a network policy allows the segregation of network traffic by namespace.
gcp_security_gke_enable_network_policy[msg21]{
 input.resource.google_container_cluster[_].network_policy.enabled  == false
 msg21 := "Network Policy should be enabled on GKE clusters"
 }

# POLICY 22 [check is same as POLICY 21]
# Clusters should be set to private
# Enabling private nodes on a cluster ensures the nodes are only available internally as they will only be assigned internal addresses.
gcp_security_gke_enable_private_cluster[msg22]{
 input.resource.google_container_cluster[_].network_policy.enabled  == false
 msg22 := "Clusters should be set to private"
 }

# POLICY 23
# Stackdriver Logging should be enabled
# StackDriver logging provides a useful interface to all of stdout/stderr for each container and should be enabled for monitoring, debugging, etc. Without Stackdriver, visibility to the cluster will be reduced.
gcp_security_gke_enable_stackdriver_logging{
  check_logging_service_exists_value
 }

check_logging_service_exists_value[msg23]{
 check_logging_services = input.resource.google_container_cluster[_]
 not check_logging_services.logging_service
 msg23 := "logging_service must be defined"
 }
 
 check_logging_service_exists_value[msg23]{
 input.resource.google_container_cluster[_].logging_service != "logging.googleapis.com/kubernetes"
 msg23 := "Stackdriver Logging should be enabled and set to the proper value logging.googleapis.com/kubernetes"
 }

# POLICY 24
# Stackdriver Monitoring should be enabled
# StackDriver monitoring aggregates logs, events, and metrics from your Kubernetes environment on GKE to help you understand your application's behavior in production.
gcp_security_gke_enable_stackdriver_monitoring{
  check_monitoring_service_exists_value
 }

check_monitoring_service_exists_value[msg24]{
 check_monitoring_services = input.resource.google_container_cluster[_]
 not check_monitoring_services.monitoring_service
 msg24 := "monitoring service must be defined"
 }
 
 check_monitoring_service_exists_value[msg24]{
 input.resource.google_container_cluster[_].monitoring_service != "monitoring.googleapis.com/kubernetes"
 msg24 := "monitoring service should be enabled and set to the proper value monitoring.googleapis.com/kubernetes"
 }

# POLICY 25
# Legacy metadata endpoints enabled
# The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers. This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata. Unless specifically required, we recommend you disable these legacy APIs. When setting the `metadata` block, the default value for `disable-legacy-endpoints` is set to `true`, they should not be explicitly enabled.
gcp_security_gke_metadata_endpoints_disabled[msg25]{
   check_metadata = input.resource.google_container_cluster[_]
   check_metadata.metadata[`disable-legacy-endpoints`] == false
   msg25 := "Legacy metadata endpoints must be enabled"
 }

# POLICY 26
# Clusters should not use basic authentication
#There are several methods of authenticating to the Kubernetes API server. In GKE, the supported methods are service account bearer tokens, OAuth tokens, and x509 client certificates. Prior to GKE's integration with OAuth, a one-time generated x509 certificate or static password were the only available authentication methods, but are now not recommended and should be disabled. These methods present a wider surface of attack for cluster compromise and have been disabled by default since GKE version 1.12. If you are using legacy authentication methods, we recommend that you turn them off. Authentication with a static password is deprecated and has been removed since GKE version 1.19.
gcp_security_gke_no_basic_authentication[msg26]{
   input.resource.google_container_cluster[_].master_auth.username == ""
   msg26 := "Legacy metadata endpoints must be enabled -Username must not be empty"
 } els[msg26] = true {
   input.resource.google_container_cluster[_].master_auth.username == null
   msg26 := "Legacy metadata endpoints must be enabled -Username must not be null"
 } els[msg26] = true {
   input.resource.google_container_cluster[_].master_auth.password == ""
   msg26 := "Legacy metadata endpoints must be enabled - Password must not be empty"
 } els[msg26] = true {
   input.resource.google_container_cluster[_].master_auth.password == null
   msg26 := "Legacy metadata endpoints must be enabled - Password must not be null"
 }

# POLICY 27
# Clusters should not use client certificates for authentication
# There are several methods of authenticating to the Kubernetes API server. In GKE, the supported methods are service account bearer tokens, OAuth tokens, and x509 client certificates. Prior to GKE's integration with OAuth, a one-time generated x509 certificate or static password were the only available authentication methods, but are now not recommended and should be disabled. These methods present a wider surface of attack for cluster compromise and have been disabled by default since GKE version 1.12. If you are using legacy authentication methods, we recommend that you turn them off. Authentication with a static password is deprecated and has been removed since GKE version 1.19.
gcp_security_gke_no_client_cert_authentication[msg27]{
   input.resource.google_container_cluster[_].master_auth.client_certificate_config.issue_client_certificate == false
   msg27 := "Clusters should not use client certificates for authentication"
 } 

# POLICY 28
# GKE Control Plane should not be publicly accessible
# Authorized networks allow you to specify CIDR ranges and allow IP addresses in those ranges to access your cluster control plane endpoint using HTTPS. Exposing the Kubernetes control plane to the public internet by specifying a CIDR block of "0.0.0.0/0" is not recommended. Public clusters can have up to 50 authorized network CIDR ranges; private clusters can have up to 100.
gcp_security_gke_no_public_control_plane[msg28]{
   some i
   input.resource.google_container_cluster[_].master_authorized_networks_config[i].cidr_blocks[j].cidr_block == "0.0.0.0/0"
   msg28 := "GKE Control Plane should not be publicly accessible"
 } 

# POLICY 29
# Node metadata value disables metadata concealment
# GKE metadata concealment protects some potentially sensitive system metadata from user workloads running on your cluster. Metadata concealment is scheduled to be deprecated in the future and Google recommends using Workload Identity instead of metadata concealment. This check is looking for configuration that exposes metadata completely.
gcp_security_gke_node_metadata_security[msg29]{
   input.resource.google_container_node_pool[_].node_config.workload_metadata_config.node_metadata == "EXPOSE"
   msg29 := "Node metadata value disables metadata concealment"
 } els[msg29] = true {
   input.resource.google_container_node_pool[_].node_config.workload_metadata_config.node_metadata == "UNSPECIFIED"
   msg29 := "Node metadata value disables metadata concealment"
 }

# POLICY 30
# Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image
# GKE supports several OS image types but COS_CONTAINERD is the recommended OS image to use on cluster nodes for enhanced security. COS_CONTAINERD is the recommended OS image to use on cluster nodes.
gcp_security_gke_node_pool_uses_cos[msg30]{
   input.resource.google_container_node_pool[_].node_config.image_type != "COS_CONTAINERD"
   msg30 := "Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image"
 } 

# POLICY 31
# Shielded GKE nodes not enabled
# Node identity and integrity can't be verified without shielded GKE nodes. CIS GKE Benchmark Recommendation: 6.5.5. Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters
gcp_security_gke_node_shielding_enabled[msg31]{
   input.resource.google_container_cluster[_].enable_shielded_nodes == false
   msg31 := "Shielded GKE nodes not enabled"
 } 

# POLICY 32
# Clusters should be configured with Labels
# Cluster labels are key-value pairs that helps you organize your Google Cloud clusters. You can attach a label to each resource, then filter the resources based on their labels. Information about labels is forwarded to the billing system, so you can break down your billed charges by label.\n\nThe `resource_labels` argument is optional when using the `google_container_cluster` resource.
gcp_security_gke_use_cluster_labels[msg32]{
   resource_label_check = input.resource.google_container_cluster[_]
   not resource_label_check.resource_labels
   msg32 := "Clusters should be configured with Labels"
 } 

# POLICY 33
# Legacy ABAC permissions are enabled
# Cluster labels are key-value pairs that helps you organize your Google Cloud clusters. You can attach a label to each resource, then filter the resources based on their labels. Information about labels is forwarded to the billing system, so you can break down your billed charges by label.\n\nThe `resource_labels` argument is optional when using the `google_container_cluster` resource.
gcp_security_gke_use_rbac_permissions[msg33]{
   input.resource.google_container_cluster[_].enable_legacy_abac == true
   msg33 := "Legacy ABAC permissions are enabled"
 } 

# POLICY 34
# Checks for service account defined for GKE nodes
# Each GKE node has an Identity and Access Management (IAM) Service Account associated with it. By default, nodes are given the Compute Engine default service account, which you can find by navigating to the IAM section of the Cloud Console. This account has broad access by default, making it useful to wide variety of applications, but it has more permissions than are required to run your Kubernetes Engine cluster. You should create and use a minimally privileged service account for your nodes to use instead of the Compute Engine default service account.
gcp_security_gke_use_service_account{
  check_google_container_cluster_node_config
 } 

check_google_container_cluster_node_config [msg34]{
  check_service_account = input.resource.google_container_cluster[_]
  not check_service_account.node_config.service_account
  msg34 := "Checks for service account defined for GKE nodes - google_container_cluster "
}

check_google_container_cluster_node_config[msg34]{
  check_service_account = input.resource.google_container_node_pool[_]
  not check_service_account.node_config.service_account
  msg34 := "Checks for service account defined for GKE nodes -google_container_node_pool"
}
