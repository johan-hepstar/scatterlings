import boto3
import ipaddress
import json
import os
import socket

from datetime import datetime

url_ip_dict = {}

def lambda_handler(event, context):
    try:
        print(f"----------------------------------------------------------------------")
        print(f"-----> production-app03-port-22-sg <-----")
        print(f"----------------------------------------------------------------------")
        sg_22_fn = os.environ.get('SG_APP03_22_FILENAME')
        production_sg_app03_22_id = os.environ.get('PRODUCTION_SG_APP03_22_ID')
        read_and_set_rules([sg_22_fn], [production_sg_app03_22_id], 22)

        print(f"----------------------------------------------------------------------")
        print(f"-----> production-port-25-sg <-----")
        print(f"----------------------------------------------------------------------")
        sg_25_fn = os.environ.get('SG_25_FILENAME')
        production_sg_25_id = os.environ.get('PRODUCTION_SG_25_ID')
        read_and_set_rules([sg_25_fn], [production_sg_25_id], 25)

        print(f"----------------------------------------------------------------------")
        print(f"-----> collection-port-80-sg <-------")
        print(f"-----> production-port-80-sg <-------")
        print(f"----------------------------------------------------------------------")
        sg_80_fn = os.environ.get('SG_80_FILENAME')
        collection_sg_80_id = os.environ.get('COLLECTION_SG_80_ID')
        production_sg_80_id = os.environ.get('PRODUCTION_SG_80_ID')
        read_and_set_rules([sg_80_fn], [collection_sg_80_id, production_sg_80_id], 80)

        print(f"----------------------------------------------------------------------")
        print(f"-----> collection-port-123-sg <-------")
        print(f"-----> production-port-123-sg <-------")
        print(f"----------------------------------------------------------------------")
        sg_123_fn = os.environ.get('SG_123_FILENAME')
        collection_sg_123_id = os.environ.get('COLLECTION_SG_123_ID')
        production_sg_123_id = os.environ.get('PRODUCTION_SG_123_ID')
        read_and_set_rules([sg_123_fn], [collection_sg_123_id, production_sg_123_id], 80)

        print(f"----------------------------------------------------------------------")
        print(f"-----> collection-port-587-sg <-------")
        print(f"-----> production-port-587-sg <-------")
        print(f"----------------------------------------------------------------------")
        sg_587_fn = os.environ.get('SG_587_FILENAME')
        collection_sg_587_id = os.environ.get('COLLECTION_SG_587_ID')
        production_sg_587_id = os.environ.get('PRODUCTION_SG_587_ID')
        read_and_set_rules([sg_587_fn], [collection_sg_587_id, production_sg_587_id], 587)

        # -----> All AWS Updates <-------
        sg_aws_fn = os.environ.get('SG_AWS_443_FILENAME')

        # -----> All Ubuntu Updates <-------
        sg_ubuntu_fn = os.environ.get('SG_UBUNTU_443_FILENAME')

        # -----> All Jumpbox Updates <-------
        sg_jb_fn = os.environ.get('SG_JB_443_FILENAME')

        # -----> All Hepstar Updates <-------
        sg_hepstar_fn = os.environ.get('SG_HEPSTAR_443_FILENAME')

        #-----> All AppServer Updates <-------
        sg_appserver_fn = os.environ.get('SG_APPSERVER_443_FILENAME')
        
        print(f"----------------------------------------------------------------------")
        print(f"---------> collection-jb-port-443-sg <----------")
        print(f"---------> production-jb-port-443-sg <----------")
        print(f"----------------------------------------------------------------------")
        collection_sg_jb_id = os.environ.get('COLLECTION_SG_JB_443_ID')
        production_sg_jb_id = os.environ.get('PRODUCTION_SG_JB_443_ID')
        read_and_set_rules([sg_aws_fn, sg_ubuntu_fn, sg_jb_fn], [collection_sg_jb_id, production_sg_jb_id], 443)

        print(f"----------------------------------------------------------------------")
        print(f"---------> collection-api-port-443-sg <----------")
        print(f"----------------------------------------------------------------------")
        sg_collection_api_fn = os.environ.get('SG_API_443_FILENAME')
        sg_collection_api_id = os.environ.get('COLLECTION_SG_API_443_ID')
        read_and_set_rules([sg_aws_fn, sg_ubuntu_fn, sg_collection_api_fn], [sg_collection_api_id], 443)

        print(f"----------------------------------------------------------------------")
        print(f"---------> collection-wazuh-port-443-sg <----------")
        print(f"----------------------------------------------------------------------")
        sg_wazuh_fn = os.environ.get('SG_WAZUH_443_FILENAME')
        sg_wazuh_id = os.environ.get('COLLECTION_SG_WAZUH_443_ID')
        read_and_set_rules([sg_aws_fn, sg_ubuntu_fn, sg_wazuh_fn], [sg_wazuh_id], 443)

        print(f"----------------------------------------------------------------------")
        print(f"---------> production-web-port-443-sg <----------")
        print(f"----------------------------------------------------------------------")
        sg_prod_web_id = os.environ.get('PRODUCTION_SG_WEB_443_ID')
        read_and_set_rules([sg_aws_fn, sg_ubuntu_fn, sg_hepstar_fn], [sg_prod_web_id], 443)

        print(f"----------------------------------------------------------------------")
        print(f"---------> production-app-port-443-sg <----------")
        print(f"----------------------------------------------------------------------")
        sg_prod_app_id = os.environ.get('PRODUCTION_SG_APP_443_ID')
        read_and_set_rules([sg_appserver_fn], [sg_prod_app_id], 443)

        print(f"----------------------------------------------------------------------")
        print(f"---------> db-sg <----------")
        print(f"----------------------------------------------------------------------")
        sg_collection_db_id = os.environ.get('COLLECTION_SG_DB_443_ID')
        sg_collection_uat_db_id = os.environ.get('COLLECTION_UAT_SG_DB_443_ID')
        sg_production_db_id = os.environ.get('PRODUCTION_SG_DB_443_ID')
        read_and_set_rules([sg_aws_fn], [sg_collection_db_id, sg_collection_uat_db_id, sg_production_db_id], 443)

        #######################################################################
        #######################################################################
        # DNS UPDATES
        #######################################################################
        #######################################################################
        print(f"----------------------------------------------------------------------")
        print(f"---------> dns-updates <----------")
        print(f"----------------------------------------------------------------------")
        print(f"url_ip_dict: {url_ip_dict}")
        print(f"----------------------------------------------------------------------")

        current_datetime = datetime.now().strftime('%Y%m%d%H%M')
        filename=f'dnsupdate{current_datetime}'
        print(f"filename: {filename}")
        
        single_ip_url_dict = {}
        domain_list = []
        domain_list.append("apac.chubbdigital.com")

        for domain in domain_list:
            print(f"domain: {domain}")
            ip=url_ip_dict[domain]
            print(f"ip: {ip}")
            if ip:
                single_ip_url_dict[ip]=domain

        response=write_s3_dns(single_ip_url_dict, filename)
        print(f"response:{response}")

        ########################################################################
        ########################################################################
                
    except Exception as e:
        print(f"Main Function Execution Failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': 'Main Function Execution Failed'
        }

    return {
        'statusCode': 200,
        'body': 'Main Function Execution Succeeded'
    }

def read_and_set_rules(file_name_list, security_group_id_list, port):
    print(f"-----> read_and_set_rules")

    ips = []
    urls = []
    file_name = ''

    try:
        for file_name in file_name_list:
            file_ips, file_urls = read_s3(file_name)
            ips += file_ips
            urls += file_urls

    except Exception as e:
        print(f"** Failed to read IP's from file {file_name}: {str(e)}")
        raise RuntimeError(f"Failed to read IP's from file {file_name}") from e

    new_ips_dict = None
    try:
        # Get the IP dictionary (ip - url) for urls
        new_ips_dict = urls_to_ip_dict(port, urls)

        # Add the ips passed in to the dictionary
        for ip in ips:
            std_ip = format_ip(ip)
            if std_ip not in new_ips_dict:
                new_ips_dict[std_ip] = 'No URL'

    except Exception as e:
        print(f"** Failed to convert URL's to IP's and add: {str(e)}")
        raise RuntimeError(f"Failed to convert URL's to IP's and add {file_name}") from e

    try:
        # Set security group rules to latest DNS values
        set_egress_rules(security_group_id_list, port, new_ips_dict)

    except Exception as e:
        print(f"** Failed to add new security group rules for security group: {str(e)}")
        raise RuntimeError(f"Failed to add new security group rules for security group: ") from e

def read_s3(file_name_str):
    print(f"-----> read_s3")
    
    ips = []
    urls = []

    region = os.environ.get('AWS_REGION')
    bucket_name = os.environ.get('S3_BUCKET_NAME')
    read_folder_name = os.environ.get('S3_READ_FOLDER_NAME')
    file_name = os.environ.get(file_name_str)
    file_location = read_folder_name + '/' + file_name_str

    print(f"read_folder_name: {read_folder_name}")
    print(f"file_location: {file_location}")

    s3_client = boto3.client('s3', region_name = region)
    response = s3_client.get_object(Bucket=bucket_name, Key=file_location)
    print(f"response: {response}")

    lines = response['Body'].read().decode('utf-8').strip().split('\n')
    for line in lines:
        if not line.startswith('#'):        # is not a comment
            s_line = line.strip()
            if s_line:                      # is not an empty line
                if valid_ip(s_line):        # is an ip address
                    ips.append(s_line)
                else:                       # is a (potential) hostname
                    urls.append(s_line)

    return ips, urls

def write_s3_dns(ip_url_dict, file_name):
    print(f"-----> write_s3_dns")
        
    region = os.environ.get('AWS_REGION')
    print(f"-----> region: {region}")
    bucket_name = os.environ.get('S3_BUCKET_NAME')
    print(f"-----> bucket_name: {bucket_name}")
    folder_name = os.environ.get('S3_WRITE_FOLDER_NAME')
    print(f"-----> folder_name: {folder_name}")

    # DELETE ALL PREVIOUS FILES
    s3_client = boto3.client('s3', region_name = region)
    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=folder_name)
    files_in_folder = response["Contents"]
    files_to_delete = []
    for f in files_in_folder:
        files_to_delete.append({"Key": f["Key"]})

    print(f"-----> files_to_delete: {files_to_delete}")
    response = s3_client.delete_objects(
        Bucket=bucket_name, Delete={"Objects": files_to_delete}
    )
    print(f"-----> response: {response}")

    file_location = folder_name + '/' + file_name
    print(f"-----> file_location: {file_location}")
    
    file_content = ''
    for key, value in ip_url_dict.items():  
        file_content+=f'{key} {value}\n'
    print(f"-----> file_content: {file_content}")

    # Write file to S3
    s3_client = boto3.client('s3', region_name = region)
    s3_client.put_object(Bucket=bucket_name, Key=file_location, Body=file_content)

    print(f"File {file_name} written to S3 bucket {bucket_name}")



def valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except Exception as e:
        return False

def urls_to_ip_dict(port, urls):
    print(f"-----> urls_to_ip_dict")
    ip_dict = {}
    for url in urls:
        try:
            addr_families = socket.getaddrinfo(url, port)
            if addr_families and len(addr_families) > 0:
                for addr_family in addr_families:
                    ip = addr_family[4][0]
                    
                    if url not in url_ip_dict:
                        url_ip_dict[url] = ip

                    std_ip = format_ip(ip)
                    if std_ip not in ip_dict:
                        ip_dict[std_ip] = url

            else:
                print(f"** No DNS information found: {url}")

        except Exception as e:
            print(f"** An error occurred for {url}: {e}")

    return ip_dict

def format_ip(ip):
    std_ip = ''
    if valid_ip(ip):
        if ':' in ip:
            std_ip = f"{ip}/128"
        else:
            std_ip = f"{ip}/32"
    return std_ip

def set_egress_rules(security_group_id_list, port, new_ip_dict):
    print(f"-----> set_egress_rules")

    MAX_LEN = 200

    for security_group_id in security_group_id_list:
        current_ips_dict = get_current_rule_ips_dict(security_group_id, port)
        new_ips = set(new_ip_dict.keys())
        current_ips = set(current_ips_dict.keys())

        ips_to_delete = current_ips - new_ips
        ips_to_add = new_ips - current_ips

        print(f"current_ips: {len(current_ips)}: {current_ips}")
        print(f"new_ips: {len(new_ips)}: {new_ips}")
        print(f"ips_to_delete: {len(ips_to_delete)}: {ips_to_delete}")
        print(f"ips_to_add: {len(ips_to_add)}: {ips_to_add}")

        num = len(current_ips) - len(ips_to_delete) + len(ips_to_add)
        print(f"new length would be: ------{num}------")
        if num > MAX_LEN:
            print(f"THIS WOULD BE MORE THAN THE NUMBER OF PLACES AVAILABLE!!!!")

        protocol = 'tcp'
        if port == 123:
            protocol = 'udp'

        if len(ips_to_delete) > 0:
            remove_egress_rules(security_group_id, port, protocol, current_ips_dict, ips_to_delete)
        if len(ips_to_add) > 0:
            add_egress_rules(security_group_id, port, protocol, new_ip_dict, ips_to_add)

        reload(security_group_id)

def get_current_rule_ips_dict(security_group_id, port):
    print(f"-----> get_current_rule_ips_dict")
    
    ip_dict = {}

    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups(GroupIds=[security_group_id])
    security_group = response['SecurityGroups'][0]
    rules = security_group['IpPermissionsEgress']
    for rule in rules:
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')

        if (from_port and from_port == port) or (to_port and to_port == port):
            ip_ranges = rule['IpRanges']

            for ip_range in ip_ranges:
                ip_dict[ip_range['CidrIp']] = ip_range['Description']

            ipv6_ranges = rule['Ipv6Ranges']
            for ipv6_range in ipv6_ranges:
                ip_dict[ipv6_range['CidrIpv6']] = ipv6_range['Description']

    return ip_dict

def delete_all_egress_rules(security_group_id):
    print(f"-----> delete_all_egress_rules")

    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup(security_group_id)
    rules = security_group.ip_permissions_egress
    if rules:
        response = security_group.revoke_egress(IpPermissions=security_group.ip_permissions_egress)

def add_egress_rules(security_group_id, port, protocol, new_ips_dict, ips_to_add):
    print(f"-----> add_egress_rules")

    ipv4_ranges = []
    ipv6_ranges = []
    for ip in ips_to_add:
        print(f"ip: {ip}")
        if ':' in ip:           # IPv6
            ipv6_ranges.append(dict(Description=new_ips_dict[ip], CidrIpv6=ip))
        else:                   # IPv4
            ipv4_ranges.append(dict(Description=new_ips_dict[ip], CidrIp=ip))

    ip_permissions = [ dict(IpProtocol=protocol, FromPort=port, ToPort=port, IpRanges=ipv4_ranges, Ipv6Ranges=ipv6_ranges) ]

    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup(security_group_id)
    response = security_group.authorize_egress(IpPermissions=ip_permissions)
    print(f"response: {response}")

def remove_egress_rules(security_group_id, port, protocol, old_ips_dict, ips_to_remove):
    print(f"-----> remove_egress_rules")

    ip_rangesv4 = []
    ip_rangesv6 = []
    for ip in ips_to_remove:
        print(f"ip: {ip}")
        if ':' in ip:           # IPv6
            ip_rangesv6.append(dict(Description=old_ips_dict[ip], CidrIpv6=ip))
        else:                   # IPv4
            ip_rangesv4.append(dict(Description=old_ips_dict[ip], CidrIp=ip))

    ip_permissions = [ dict(IpProtocol=protocol, FromPort=port, ToPort=port, IpRanges=ip_rangesv4, Ipv6Ranges=ip_rangesv6) ]
    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup(security_group_id)
    response = security_group.revoke_egress(IpPermissions=ip_permissions)
    print(f"response: {response}")

def reload(security_group_id):
    print(f"-----> reload")
    ec2 = boto3.resource('ec2')
    security_group = ec2.SecurityGroup(security_group_id)
    response = security_group.reload()
