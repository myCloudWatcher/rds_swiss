define :aws_swiss, \
  :aws_access_key_id => nil, \
  :aws_secret_access_key => nil, \
  :cidr => nil, \
  :port => nil, \
  :enable => true, \
  :fallback_group => nil, \
  :dbhost => nil \
do

  security_group = params[:name]
  cidr = params[:cidr]
  port = params[:port]
  fallback_group = params[:fallback_group]
  dbhost = params[:dbhost]
  
  if !port.nil?
    port = port.to_s
  end
  
  group_arg_name = SecurityGroupHoleController.get_awscli_argument_for_security_group(security_group)
  if !fallback_group.nil?
    fallback_group_arg_name = SecurityGroupHoleController.get_awscli_argument_for_security_group(fallback_group)
  end
  
  aws_instance_metadata_url = "http://169.254.169.254/latest/meta-data"
  region=%x"curl --silent #{aws_instance_metadata_url}/placement/availability-zone/"[0..-2]
  cidr=%x"curl --silent #{aws_instance_metadata_url}/public-ipv4"+'/32' if cidr.nil? || cidr.size==0
  
  command_base = SecurityGroupHoleController.awscli_command_stem(region, params[:aws_access_key_id], params[:aws_secret_access_key])

  target_name = "CIDR #{cidr}" + (port.nil? ? "" : " port #{port}") + " to " +
    (port.nil? ? "RDS DB " : "") +  "security group #{security_group}"

  include_recipe "awscli"
  require 'json'
  
  if params[:enable] # authorize
    if port.nil? # RDS security group
      ruby_block "authorize RDS ingress for #{target_name}" do
        block do
          SecurityGroupHoleController.open_rds_hole_with_fallback(security_group, fallback_group, cidr, region, params[:aws_access_key_id], params[:aws_secret_access_key], dbhost)
        end
      end
    else # EC2 security group
      ruby_block "authorize EC2 ingress for #{target_name}" do
        block do
          system(command_base + "ec2 authorize-security-group-ingress --#{group_arg_name} #{security_group} --cidr #{cidr} --protocol tcp --port #{port}")
        end
        only_if do
          str=%x^#{command_base} ec2 describe-security-groups --#{group_arg_name}s #{security_group} --query 'SecurityGroups[0].IpPermissions[*].{FromPort:FromPort, ToPort:ToPort, Protocol:IpProtocol, CIDRs:IpRanges[*].CidrIp}'^
          json=JSON.parse(str)
          json.none? { |hole|
            hole['ToPort']==port.to_i && hole['FromPort']==port.to_i && hole['Protocol']="tcp" && hole['CIDRs'].include?(cidr)
          }
        end
      end
    end
  else # revoke
    if port.nil? # RDS security group
      ruby_block "revoke RDS ingress for #{target_name}" do
        block do
          SecurityGroupHoleController.close_rds_hole_with_fallback(security_group, fallback_group, cidr, region, params[:aws_access_key_id], params[:aws_secret_access_key])
        end
      end
    else # EC2 security group
      ruby_block "revoke EC2 ingress for #{target_name}" do
        block do
          system(command_base + "ec2 revoke-security-group-ingress --#{group_arg_name} #{security_group} --cidr #{cidr} --protocol tcp --port #{port}")
        end
        # non-existent ingress can be revoked without any error, so no only_if guard here
      end
    end
  end

end
