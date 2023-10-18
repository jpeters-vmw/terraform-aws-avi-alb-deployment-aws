# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

variable "region" {
  description = "The Region that the AVI controller and SEs will be deployed to"
  type        = string
}
variable "license_tier" {
  description = "The license tier to use for Avi. Possible values are ENTERPRISE_WITH_CLOUD_SERVICES or ENTERPRISE"
  type        = string
  default     = "ENTERPRISE_WITH_CLOUD_SERVICES"
  validation {
    condition     = var.license_tier == "ENTERPRISE_WITH_CLOUD_SERVICES" || var.license_tier == "ENTERPRISE"
    error_message = "The license_tier variable must be ENTERPRISE_WITH_CLOUD_SERVICES or ENTERPRISE."
  }
}
variable "license_key" {
  description = "The license key that will be applied when the tier is set to ENTERPRISE with the license_tier variable"
  type        = string
  default     = ""
}
variable "ca_certificates" {
  description = "Import one or more Root or Intermediate Certificate Authority SSL certificates for the controller. The certificate must be in the PEM format and base64 encoded without line breaks. An example command for generating the proper format is 'base64 -w 0 ca.pem > ca.base64'"
  type = list(object({
    name        = string,
    certificate = string
  }))
  default = [{ name = "", certificate = "" }]
}
variable "portal_certificate" {
  description = "Import a SSL certificate for the controller's web portal. The key and certificate must be in the PEM format and base64 encoded without line breaks. An example command for generating the proper format is 'base64 -w 0 certificate.pem > cert.base64'"
  type = object({
    key            = string,
    certificate    = string,
    key_passphrase = optional(string)
  })
  default = { key = "", certificate = "" }
}
variable "securechannel_certificate" {
  description = "Import a SSL certificate for the controller's secure channel communication. Only if there is strict policy that requires all SSL certificates to be signed a specific CA should this variable be used otherwise the default generated certificate is recommended. The full cert chain is necessary and can be provided within the certificate PEM file or separately with the ca_certificates variable. The key and certificate must be in the PEM format and base64 encoded without line breaks. An example command for generating the proper format is 'base64 -w 0 certificate.pem > cert.base64'"
  type = object({
    key            = string,
    certificate    = string,
    key_passphrase = optional(string)
  })
  default = { key = "", certificate = "" }
}
variable "aws_access_key" {
  description = "The Access Key that will be used to deploy AWS resources"
  type        = string
  sensitive   = false
  default     = ""
}
variable "aws_secret_key" {
  description = "The Secret Key that will be used to deploy AWS resources"
  type        = string
  sensitive   = false
  default     = ""
}
variable "fips" {
  description = "Enable FIPS mode on AWS.  Specify the S3 bucket and prefix of the controller package accessible by the controller."
  type = object({
    enabled               = bool,
    s3_bucket             = string,
    s3_controller_package = string
  })
  default = { enabled = "false", s3_bucket = "", s3_controller_package = "/controller.pkg" }
}
variable "key_pair_name" {
  description = "The name of the existing EC2 Key pair that will be used to authenticate to the Avi Controller"
  type        = string
}
variable "private_key_path" {
  description = "The local private key path for the EC2 Key pair used for authenticating to the Avi Controller. Either private_key_path or private_key_contents must be supplied."
  type        = string
  sensitive   = false
  default     = null

}
variable "private_key_contents" {
  description = "The contents of the private key for the EC2 Key pair used for authenticating to the Avi Controller. Either private_key_path or private_key_contents must be supplied."
  type        = string
  sensitive   = true
  default     = null
}
variable "avi_version" {
  description = "The AVI Controller version that will be deployed"
  type        = string
}
variable "custom_ami" {
  description = "The AMI ID of a custom controller AMI.  For internal use."
  type        = string
  default     = null
}
variable "avi_upgrade" {
  description = "This variable determines if a patch upgrade is performed after install. The enabled key should be set to true and the url from the Avi Cloud Services portal for the should be set for the upgrade_file_uri key. Valid upgrade_type values are patch or system"
  sensitive   = false
  type = object({
    enabled          = bool,
    upgrade_type     = string,
    upgrade_file_uri = string
  })
  default = { enabled = "false", upgrade_type = "patch", upgrade_file_uri = "" }
}
variable "name_prefix" {
  description = "This prefix is appended to the names of the Controller and SEs"
  type        = string
}
variable "controller_ha" {
  description = "If true a HA controller cluster is deployed and configured"
  type        = bool
  default     = "false"
}
variable "register_controller" {
  description = "If enabled is set to true the controller will be registered and licensed with Avi Cloud Services. The Long Organization ID (organization_id) can be found from https://console.cloud.vmware.com/csp/gateway/portal/#/organization/info. The jwt_token can be retrieved at https://portal.avipulse.vmware.com/portal/controller/auth/cspctrllogin. Optionally the controller name and description used during the registration can be set; otherwise, the name_prefix and configure_gslb.site_name variables will be used."
  sensitive   = false
  type = object({
    enabled         = bool,
    jwt_token       = string,
    email           = string,
    organization_id = string,
    name            = optional(string),
    description     = optional(string)
  })
  default = { enabled = "false", jwt_token = "", email = "", organization_id = "" }
}
variable "create_networking" {
  description = "This variable controls the VPC and subnet creation for the AVI Controller. When set to false the custom-vpc-name and custom-subnetwork-name must be set."
  type        = bool
  default     = "true"
}
variable "create_firewall_rules" {
  description = "This variable controls the Security Group creation for the Avi deployment. When set to false the necessary security group rules must be in place before the deployment and set with the firewall_custom_security_group_ids variable"
  type        = bool
  default     = "true"
}
variable "firewall_controller_allow_source_range" {
  description = "The IP range allowed to connect to the Avi Controller. Access from all IP ranges will be allowed by default. DEPRECATED in favor of firewall_controller_allow_source_ranges"
  type        = string
  default     = null
}
variable "firewall_controller_allow_source_ranges" {
  description = "The IP range allowed to connect to the Avi Controller. Access from all IP ranges will be allowed by default"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}
variable "firewall_controller_security_group_ids" {
  description = "List of security group IDs that will be assigned to the controller. This variable must be set if the create_firewall_rules variable is set to false"
  type        = list(string)
  default     = null
}
variable "firewall_se_data_rules" {
  description = "The data plane traffic allowed for Virtual Services hosted on Services Engines. The configure_firewall_rules variable must be set to true for these rules to be created"
  type = list(object({
    protocol       = string,
    port           = string,
    allow_ip_range = string,
    description    = string
  }))
  default = [{ protocol = "tcp", port = "443", allow_ip_range = "0.0.0.0/0", description = "https" }, { protocol = "udp", port = "53", allow_ip_range = "10.0.0.0/8", description = "DNS" }]
}
variable "controller_public_address" {
  description = "This variable controls if the Controller has a Public IP Address. When set to false the Ansible provisioner will connect to the private IP of the Controller."
  type        = bool
  default     = "false"
}
variable "avi_cidr_block" {
  description = "This CIDR that will be used for creating a subnet in the AVI VPC - a /16 should be provided. This range is also used for security group rules source IP range for internal communication between the Controllers and SEs"
  type        = string
  default     = "10.255.0.0/16"
}
variable "custom_vpc_id" {
  description = "This field can be used to specify an existing VPC for the SEs. The create-networking variable must also be set to false for this network to be used."
  type        = string
  default     = null
}
variable "custom_subnet_ids" {
  description = "This field can be used to specify a list of existing VPC Subnets for the SEs. The create-networking variable must also be set to false for this network to be used."
  type        = list(string)
  default     = null
}
variable "custom_controller_subnet_ids" {
  description = "This field can be used to specify a list of existing VPC Subnets for the Controllers.  The create-networking variable must also be set to false for this network to be used."
  type        = list(string)
  default     = null
}
variable "custom_controller_name" {
  description = "This field can be used to specify a custom controller name to replace the (prefix-avi-controller) standard name.  A numeric iterator will still be appended to the custom name (1,2,3)"
  type        = string
  default     = null
}
variable "create_iam" {
  description = "Create IAM policy, roles, and instance profile for Avi AWS Full Access Cloud. If set to false the aws_access_key and aws_secret_key variables will be used for the Cloud configuration and all policy must be created as found in https://avinetworks.com/docs/latest/iam-role-setup-for-installation-into-aws/"
  type        = bool
  default     = "true"
}
variable "controller_password" {
  description = "The password that will be used authenticating with the AVI Controller. This password be a minimum of 8 characters and contain at least one each of uppercase, lowercase, numbers, and special characters"
  type        = string
  sensitive   = false
  validation {
    condition     = length(var.controller_password) > 7
    error_message = "The controller_password value must be more than 8 characters and contain at least one each of uppercase, lowercase, numbers, and special characters."
  }
}
variable "instance_type" {
  description = "The EC2 instance type for the Avi Controller"
  type        = string
  default     = "m5.2xlarge"
}
variable "boot_disk_size" {
  description = "The boot disk size for the Avi controller"
  type        = number
  default     = 128
  validation {
    condition     = var.boot_disk_size >= 128
    error_message = "The Controller root disk size should be greater than or equal to 128 GB."
  }
}
variable "se_ha_mode" {
  description = "The HA mode of the default Service Engine Group. Possible values active/active, n+m, or active/standby"
  type        = string
  default     = "active/active"
  validation {
    condition     = contains(["active/active", "n+m", "active/standby"], var.se_ha_mode)
    error_message = "Acceptable values are active/active, n+m, or active/standby."
  }
}
variable "se_instance_type" {
  description = "The instance type of the default Service Engine Group. Possible values can be found at https://aws.amazon.com/ec2/instance-types/"
  type        = string
  default     = "c5.large"
}
variable "controller_ebs_encryption" {
  description = "Enable encryption on the Controller EBS Root Volume.  The AWS Managed EBS KMS key will be used if no key is provided with the controller_ebs_encryption_key_arn variable"
  type        = bool
  default     = "true"
}
variable "se_s3_encryption" {
  description = "Enable encryption on SE S3 Bucket.  The AWS Managed S3 KMS key will be used if no key is provided with se_s3_encryption_key_arn variable"
  type        = bool
  default     = "true"
}
variable "se_ebs_encryption" {
  description = "Enable encryption on SE AMI / EBS Volumes.  The AWS Managed EBS KMS key will be used if no key is provided with se_ebs_encryption_key_arn variable"
  type        = bool
  default     = "true"
}
variable "controller_ebs_encryption_key_arn" {
  description = "AWS Resource Name of an existing KMS key for the Controller EBS (controller_ebs_encryption must be set to true)"
  type        = string
  default     = null
}
variable "se_s3_encryption_key_arn" {
  description = "AWS Resource Name of an existing KMS key for SE S3 Bucket (se_s3_encryption must be set to true)"
  type        = string
  default     = null
}
variable "se_ebs_encryption_key_arn" {
  description = "AWS Resource Name of an existing KMS key for SE AMI/EBS (se_ebs_encryption must be set to true)"
  type        = string
  default     = null
}
variable "custom_tags" {
  description = "Custom tags added to AWS Resources created by the module"
  type        = map(string)
  default     = {}
}
variable "dns_servers" {
  description = "The optional DNS servers that will be used for local DNS resolution by the controller. Example [\"8.8.4.4\", \"8.8.8.8\"]"
  type        = list(string)
  default     = null
}
variable "dns_search_domain" {
  description = "The optional DNS search domain that will be used by the controller"
  type        = string
  default     = null
}
variable "ntp_servers" {
  description = "The NTP Servers that the Avi Controllers will use. The server should be a valid IP address (v4 or v6) or a DNS name. Valid options for type are V4, DNS, or V6"
  type = list(object({
    addr = string,
    type = string
  }))
  default = [{ addr = "0.us.pool.ntp.org", type = "DNS" }, { addr = "1.us.pool.ntp.org", type = "DNS" }, { addr = "2.us.pool.ntp.org", type = "DNS" }, { addr = "3.us.pool.ntp.org", type = "DNS" }]
}
variable "email_config" {
  description = "The Email settings that will be used for sending password reset information or for trigged alerts. The default setting will send emails directly from the Avi Controller"
  sensitive   = false
  type = object({
    smtp_type        = string,
    from_email       = string,
    mail_server_name = string,
    mail_server_port = string,
    auth_username    = string,
    auth_password    = string
  })
  default = { smtp_type = "SMTP_LOCAL_HOST", from_email = "admin@avicontroller.net", mail_server_name = "localhost", mail_server_port = "25", auth_username = "", auth_password = "" }
}
variable "configure_controller" {
  description = "Configure the Avi Cloud via Ansible after controller deployment. If not set to true this must be done manually with the desired config"
  type        = bool
  default     = "true"
}
variable "configure_dns_profile" {
  description = "Configure a DNS Profile for DNS Record Creation for Virtual Services. The usable_domains is a list of domains that Avi will be the Authoritative Nameserver for and NS records may need to be created pointing to the Avi Service Engine addresses. Supported profiles for the type parameter are AWS or AVI. The AWS DNS Profile is only needed when the AWS Account used for Route53 is different than the Avi Controller and the configure_dns_route_53 variable can be used otherwise"
  type = object({
    enabled        = bool,
    type           = optional(string, "AVI"),
    usable_domains = list(string),
    ttl            = optional(string, "30"),
    aws_profile = optional(object({
      iam_assume_role   = string,
      region            = string, vpc_id = string,
      access_key_id     = string,
      secret_access_key = string
    }))
  })
  default = { enabled = false, type = "AVI", usable_domains = [] }
  validation {
    condition     = contains(["AWS", "AVI"], var.configure_dns_profile.type)
    error_message = "Supported DNS Profile types are 'AWS' or 'AVI'"
  }
}
variable "configure_dns_route_53" {
  description = "Configures Route53 DNS integration in the AWS Cloud configuration. The following variables must be set to false if enabled: configure_dns_profile, configure_dns_vs, configure_gslb"
  type        = bool
  default     = "false"
}
variable "configure_dns_vs" {
  description = "Create Avi DNS Virtual Service. The subnet_name parameter must be an existing AWS Subnet. If the allocate_public_ip parameter is set to true a EIP will be allocated for the VS. The VS IP address will automatically be allocated via the AWS IPAM"
  type = object({
    enabled            = bool,
    subnet_name        = string,
    allocate_public_ip = bool
  })
  default = { enabled = "false", subnet_name = "", allocate_public_ip = "false" }
}
variable "configure_gslb" {
  description = "Configures GSLB. In addition the configure_dns_vs variable must also be set for GSLB to be configured. See the GSLB Deployment README section for more information."
  type = object({
    enabled         = bool,
    leader          = optional(bool, false),
    site_name       = string,
    domains         = optional(list(string)),
    create_se_group = optional(bool, true),
    se_size         = optional(string, "c5.xlarge"),
    additional_sites = optional(list(object({
      name            = string,
      ip_address_list = list(string)
    }))),
  })
  default = { enabled = "false", site_name = "", domains = [""] }
}
variable "s3_backup_bucket" {
  description = "Name of the S3 bucket for Controller configuration backups"
  type        = string
  default     = null
}
variable "s3_backup_retention" {
  description = "Number of days to keep backups in S3 bucket"
  type        = number
  default     = 4
}
