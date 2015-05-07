module DBTester
  def DBTester.test_db_connection( dbhost )
    require 'open3'
    connectionerror = 1
    attempt = 0
    maxattempts = 8
    while ( (connectionerror == 1) && ( ( maxattempts < 0 ) || ( attempt < maxattempts ) ) )
      Chef::Log.info( "Testing web server's database connection to '" + dbhost + "'..." )
      stdin, stdout, stderr, wait_thr = Open3.popen3( 'nc', '-w', '10', '-z', dbhost, '3306' )
      stdout.gets(nil)
      stdout.close
      stderr.gets(nil)
      stderr.close
      exit_code = wait_thr.value
      connectionerror = exit_code.exitstatus
      if ( connectionerror == 1 )
        Chef::Log.info( "Connection not ready yet.  Returned error of '" + connectionerror.to_s + "'.  Sleeping..." )
        sleep( 30 )
      end
      attempt = attempt + 1
    end
    if ( connectionerror == 1 )
      Chef::Log.info("Max attempts reached... giving up.")
    else
      Chef::Log.info("Connection okay!")
    end
  end
end

module SecurityGroupHoleController
  
  def self.awscli_command_stem(region, aws_access_key_id, aws_secret_access_key)
    command_base = ""
    if !aws_access_key_id.nil? && !aws_secret_access_key.nil?
      command_base = "AWS_ACCESS_KEY_ID=#{aws_access_key_id} AWS_SECRET_ACCESS_KEY=#{aws_secret_access_key} "
    end
    command_base << "/usr/local/bin/aws --region #{region} "
    command_base
  end
  
  def self.get_awscli_argument_for_security_group(security_group)
    security_group[/sg-([0-9a-f]{8})/, 1].nil? ? "group-name" : "group-id"
  end
  
  def self.get_rds_cidr_holes(security_group, region, aws_access_key_id, aws_secret_access_key)
    command_base = awscli_command_stem(region, aws_access_key_id, aws_secret_access_key)
    str=%x^#{command_base} rds describe-db-security-groups --db-security-group-name #{security_group}^
    json=JSON.parse(str)
    json['DBSecurityGroups'].first['IPRanges'].reduce([]) { |result, cidrHash| 
      if ["authorized", "authorizing"].include?(cidrHash['Status'])
        result << cidrHash['CIDRIP']
      end
      result
    }
  end
  
  def self.detect_rds_hole(security_group, cidr, region, aws_access_key_id, aws_secret_access_key)
    cidr_holes = get_rds_cidr_holes(security_group, region, aws_access_key_id, aws_secret_access_key)
    # the return value - array of [ hole_exists, num_holes ]
    [ cidr_holes.include?(cidr), cidr_holes.size ]
  end
  
  def self.open_rds_hole_if_necessary(security_group, cidr, region, aws_access_key_id, aws_secret_access_key, dbhost)
    hole_exists, num_holes = detect_rds_hole(security_group, cidr, region, aws_access_key_id, aws_secret_access_key)
    if !hole_exists
      command_base = awscli_command_stem(region, aws_access_key_id, aws_secret_access_key)
      shell = Mixlib::ShellOut.new(command_base + "rds authorize-db-security-group-ingress --db-security-group-name #{security_group} --cidrip #{cidr}")
      shell.run_command
      if shell.exitstatus != 0
        # failed to poke hole.
        Chef::Log.info("Failed to poke hole in RDS security group #{security_group} for cidr #{cidr}")
        Chef::Log.info('STDOUT: ' + shell.stdout)
        Chef::Log.info('STDERR: '+ shell.stderr)
        Chef::Log.info("There are #{num_holes} holes in the security group #{security_group}")
        false
      else
        # hole poked successfully
        Chef::Log.info("Successfully poked hole in RDS security group #{security_group} for cidr #{cidr}")
        Chef::Log.info("There are now #{num_holes+1} holes in the security group #{security_group}")
        DBTester.test_db_connection( dbhost )
        true
      end
    else
      # hole already exists
      Chef::Log.info("Hole in RDS security group #{security_group} for cidr #{cidr} already exists among #{num_holes} holes")
      true
    end
  end
  
  def self.close_rds_hole_if_necessary(security_group, cidr, region, aws_access_key_id, aws_secret_access_key)
    hole_exists, num_holes = detect_rds_hole(security_group, cidr, region, aws_access_key_id, aws_secret_access_key)
    if hole_exists
      command_base = awscli_command_stem(region, aws_access_key_id, aws_secret_access_key)
      shell = Mixlib::ShellOut.new(command_base + "rds revoke-db-security-group-ingress --db-security-group-name #{security_group} --cidrip #{cidr}")
      shell.run_command
      if shell.exitstatus != 0
        # failed to plug hole
        Chef::Log.info("Failed to plug hole in RDS security group #{security_group} for cidr #{cidr}")
        Chef::Log.info('STDOUT: ' + shell.stdout)
        Chef::Log.info('STDERR: '+ shell.stderr)
        Chef::Log.info("There are #{num_holes} holes in the security group #{security_group}")
        false
      else
        # plugged hole
        Chef::Log.info("Successfully plugged hole in RDS security group #{security_group} for cidr #{cidr}")
        Chef::Log.info("There are now #{num_holes-1} holes in the security group #{security_group}")
        true
      end
    else
      # no hole in this security group
      Chef::Log.info("Hole in RDS security group #{security_group} for cidr #{cidr} is not present among #{num_holes} holes")
      true
    end
  end
  
  def self.open_rds_hole_with_fallback(security_group, fallback_group, cidr, region, aws_access_key_id, aws_secret_access_key, dbhost)
    if !open_rds_hole_if_necessary(security_group, cidr, region, aws_access_key_id, aws_secret_access_key, dbhost)
      # failed to poke hole in specified security group
      if !fallback_group.nil?
        Chef::Log.info("Trying to poke hole in fallback security group #{fallback_group}")
        if !open_rds_hole_if_necessary(fallback_group, cidr, region, aws_access_key_id, aws_secret_access_key, dbhost)
          # failed fallback also
          raise "Failed to poke hole in fallback security group #{fallback_group}"
        end
      else
        # no fallback security group
        raise "Failed to poke hole in RDS security group #{security_group} and no fallback group specified"
      end
    end
  end
  
  def self.close_rds_hole_with_fallback(security_group, fallback_group, cidr, region, aws_access_key_id, aws_secret_access_key)
    plugged = close_rds_hole_if_necessary(security_group, cidr, region, aws_access_key_id, aws_secret_access_key)
    if plugged
      # hole is not present in specified security group. Make sure it's not in the fallback group either.
      if !fallback_group.nil?
        Chef::Log.info("Plugging hole in fallback security group #{fallback_group}")
        plugged = close_rds_hole_if_necessary(fallback_group, cidr, region, aws_access_key_id, aws_secret_access_key)
      end
    end
    if !plugged
      # failed to plug hole
      raise "Failed to plug hole in RDS security group #{security_group} fallback group #{fallback_group}"
    end
  end
  
end
