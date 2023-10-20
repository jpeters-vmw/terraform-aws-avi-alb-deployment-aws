# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0
---
- name: Avi Controller Configuration
  hosts: localhost
  connection: local
  gather_facts: no
  vars:
    ansible_become_password: "{{ password }}"
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
    name_prefix: ${name_prefix}
    ca_certificates:
      ${ indent(6, yamlencode(ca_certificates))}
    portal_certificate:
      ${ indent(6, yamlencode(portal_certificate))}
    securechannel_certificate:
      ${ indent(6, yamlencode(securechannel_certificate))}
    controller_ip:
      ${ indent(6, yamlencode(controller_ip))}
    controller_names:
      ${ indent(6, yamlencode(controller_names))}
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

    - name: Import CA SSL Certificates
      avi_sslkeyandcertificate:
        avi_credentials: "{{ avi_credentials }}"
        name: "{{ item.name }}"
        certificate_base64: true
        certificate:
          certificate: "{{ item.certificate }}"
        format: SSL_PEM
        type: SSL_CERTIFICATE_TYPE_CA
      when: ca_certificates.0.certificate != ""
      ignore_errors: yes
      loop: "{{ ca_certificates }}"

    - name: Import Portal SSL Certificate
      avi_sslkeyandcertificate:
        avi_credentials: "{{ avi_credentials }}"
        name: "{{ name_prefix }}-Portal-Cert"
        certificate_base64: true
        key_base64: true
        key: "{{ portal_certificate.key }}"
        certificate:
          certificate: "{{ portal_certificate.certificate }}"
        key_passphrase: "{{ portal_certificate.key_passphrase | default(omit) }}"
        format: SSL_PEM
        type: SSL_CERTIFICATE_TYPE_SYSTEM
      when: portal_certificate.certificate != ""
      register: portal_cert
      ignore_errors: yes

    - name: Import Secure Channel SSL Certificate
      avi_sslkeyandcertificate:
        avi_credentials: "{{ avi_credentials }}"
        name: "{{ name_prefix }}-Secure-Channel-Cert"
        certificate_base64: true
        key_base64: true
        key: "{{ securechannel_certificate.key }}"
        certificate:
          certificate: "{{ securechannel_certificate.certificate }}"
        key_passphrase: "{{ securechannel_certificate.key_passphrase | default(omit) }}"
        format: SSL_PEM
        type: SSL_CERTIFICATE_TYPE_SYSTEM
      when: securechannel_certificate.certificate != ""
      register: securechannel_cert

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
%{ if portal_certificate.certificate != "" ~}
        portal_configuration:
          sslkeyandcertificate_refs:
            - "/api/sslkeyandcertificate?name={{ name_prefix }}-Portal-Cert"
%{ endif ~}
%{ if securechannel_certificate.certificate != "" ~}
        secure_channel_configuration:
          sslkeyandcertificate_refs:
            - "/api/sslkeyandcertificate?name={{ name_prefix }}-Secure-Channel-Cert"
%{ endif ~}
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
      delay: 10
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
        
        - name: Fix avi_api_session bug
          lineinfile:
            path: /etc/ansible/collections/ansible_collections/vmware/alb/plugins/modules/avi_api_session.py
            regexp: '^\s*api_get_not_allowed ='
            line: '    api_get_not_allowed = ["cluster", "gslbsiteops", "server", "nsxt", "vcenter", "macro", "systemconfiguration"]'
          become: true
          tags: fips_debug

        - name: Fix avi_api_session bug
          lineinfile:
            path: /etc/ansible/collections/ansible_collections/vmware/alb/plugins/modules/avi_api_session.py
            regexp: '^\s*sub_api_get_not_allowed ='
            line: '    sub_api_get_not_allowed = ["scaleout", "scalein", "upgrade", "rollback", "compliancemode"]'
          become: true
          tags: fips_debug

        - name: Enable FIPS mode
          avi_api_session:
            avi_credentials: "{{ avi_credentials }}"
            http_method: post
            timeout: 1200
            path: systemconfiguration/compliancemode
            data:
              fips_mode: true
          register: _fips_mode
          until: 
            - _fips_mode.failed == false
            - _fips_mode.failed is defined
          retries: 10
          delay: 60
          tags: fips_debug

        - name: Wait for 10 minutes before continuing
          wait_for:
            timeout: 600
          tags: fips_debug
      when: fips.enabled
