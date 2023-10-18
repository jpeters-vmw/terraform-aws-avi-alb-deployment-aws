# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0
---
- name: Avi Controller Configuration
  hosts: localhost
  connection: local
  gather_facts: no
  vars:
    avi_credentials:
        controller: "{{ controller_ip[0] }}"
        username: "{{ username }}"
        password: "{{ password }}"
        api_version: "{{ api_version }}"
    controller_ip:
      ${ indent(6, yamlencode(controller_ip))}
    username: "admin"
    password: "{{ password }}"
    api_version: ${avi_version}
    aws_region: ${aws_region}
    aws_partition: ${aws_partition}
    fips:
      ${ indent(6, yamlencode(fips))}
    license_tier: ${license_tier}
    email_config:
      ${ indent(6, yamlencode(email_config))}
%{ if dns_servers != null ~}
    dns_servers:
%{ for item in dns_servers ~}
      - addr: "${item}"
        type: "V4"
%{ endfor ~}
    dns_search_domain: ${dns_search_domain}
%{ endif ~}
    ntp_servers:
%{ for item in ntp_servers ~}
      - server:
          addr: "${item.addr}"
          type: "${item.type}"
%{ endfor ~}
%{ if aws_partition == "aws-us-gov" ~}
    motd: >
      Attention!!

      The use of this system is restricted to authorized users only. Unauthorized
      access, use, or modification of this computer system or of the data contained
      herein or in transit to/from this system constitutes a violation of Title 18,
      United States Code, Section 1030 and state criminal and civil laws. 
      

      These systems and equipment are subject to monitoring to ensure proper performance
      of applicable system and security features. Such monitoring may result in the
      acquisition, recording and analysis of all data being communicated, transmitted,
      processed, or stored in this system by a user, including personal information.


      Evidence of unauthorized use collected during monitoring may be used for
      administrative, criminal, or other adverse action. Unauthorized use may subject
      you to criminal prosecution. Use of this computer system, authorized or
      unauthorized, constitutes consent to monitoring of this system. 

      
      By accessing this information system, the user acknowledges and accepts the
      aforementioned terms and conditions.
%{ endif ~}

  tasks:
    - name: Wait for Controller to become ready
      uri:
        url: "https://localhost/api/initial-data"
        validate_certs: no
        status_code: 200
      register: result
      until: result.status == 200
      retries: 300
      delay: 10

    - name: Configure System Configurations
      avi_systemconfiguration:
        avi_credentials: "{{ avi_credentials }}"
        state: present   
        default_license_tier: "{{ license_tier }}"
        email_configuration: "{{ email_config }}"
        global_tenant_config:
          se_in_provider_context: true
          tenant_access_to_provider_se: true
          tenant_vrf: false
%{ if dns_servers != null ~}
        dns_configuration:
          server_list: "{{ dns_servers }}"
          search_domain: "{{ dns_search_domain }}"
%{ endif ~}
        ntp_configuration:
          ntp_servers: "{{ ntp_servers }}"        
        portal_configuration:
          allow_basic_authentication: false
          disable_remote_cli_shell: false
          enable_clickjacking_protection: true
          enable_http: true
          enable_https: true
          password_strength_check: true
          redirect_to_https: true
          use_uuid_from_input: false
%{ if aws_partition == "aws-us-gov" ~}
        linux_configuration:
          banner: "{{ motd }}"
%{ endif ~}
        welcome_workflow_complete: true
      until: sysconfig is not failed
      retries: 30
      delay: 5
      register: sysconfig

    - name: Enable FIPS 
      block:
        - name: Ensure AWS Config folder exists
          file:
            path: /home/admin/.aws
            state: directory
            group: admin
            owner: admin
        
        - name: Configure AWS Instance Profile Credential
          copy:
            content: |
              [default]
              credential_source = Ec2InstanceMetadata
              region = {{ aws_region }}
            dest: /home/admin/.aws/config
            group: admin
            owner: admin
        
        - name: Download controller.pkg from {{ fips.s3_bucket }}
          command: aws s3 cp s3://{{ fips.s3_bucket }}{{ fips.s3_controller_package }} /tmp/fips-controller.pkg

        - name: Import FIPS controller package
          avi_api_image:
            avi_credentials: "{{ avi_credentials }}"
            file_path: /tmp/fips-controller.pkg
            api_version: "{{ avi_credentials.api_version }}"
            timeout: 3000
          become: true
        
        - name: Cleanup FIPS controller package
          file:
            path: /tmp/fips-controller.pkg
            state: absent
      when: fips.enabled

    - name: Configure FIPS System Configurations
      avi_systemconfiguration:
        avi_credentials: "{{ avi_credentials }}"
        state: present   
        default_license_tier: "{{ license_tier }}"
        email_configuration: "{{ email_config }}"
        fips_mode: "{{ fips.enabled }}"
        global_tenant_config:
          se_in_provider_context: true
          tenant_access_to_provider_se: true
          tenant_vrf: false
%{ if dns_servers != null ~}
        dns_configuration:
          server_list: "{{ dns_servers }}"
          search_domain: "{{ dns_search_domain }}"
%{ endif ~}
        ntp_configuration:
          ntp_servers: "{{ ntp_servers }}"        
        portal_configuration:
          allow_basic_authentication: false
          disable_remote_cli_shell: false
          enable_clickjacking_protection: true
          enable_http: true
          enable_https: true
          password_strength_check: true
          redirect_to_https: true
          use_uuid_from_input: false
%{ if aws_partition == "aws-us-gov" ~}
        linux_configuration:
          banner: "{{ motd }}"
%{ endif ~}
        welcome_workflow_complete: true
      until: sysconfig is not failed
      retries: 30
      delay: 5
      register: sysconfig
      when: fips.enabled
