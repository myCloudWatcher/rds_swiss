aws_swiss node[:aws_swiss][:security_group] do
  aws_access_key_id     node[:aws_swiss][:aws_access_key_id]
  aws_secret_access_key node[:aws_swiss][:aws_secret_access_key]
  port                  node[:aws_swiss][:port]     # May be nil
  enable                true
  fallback_group        node[:aws_swiss][:fallback_group] # May be nil
end

module DBTester
  def DBTester.test_db_connection( dbhost )
    require 'open3'
    connectionerror = 1
    attempt = 0
    maxattempts = 5
    while ( (connectionerror == 1) && ( ( maxattempts < 0 ) || ( attempt < maxattempts ) ) )
      Chef::Log.info( "Testing web server's database connection to '" + dbhost + "'..." )
      stdin, stdout, stderr, wait_thr = Open3.popen3( 'nc', '-w', '5', '-z', dbhost, '3306' )
      stdout.gets(nil)
      stdout.close
      stderr.gets(nil)
      stderr.close
      exit_code = wait_thr.value
      connectionerror = exit_code.exitstatus
      if ( connectionerror == 1 )
        Chef::Log.info( "Connection not ready yet.  Returned error of '" + connectionerror.to_s + "'.  Sleeping..." )
        sleep( 60 )
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

DBTester.test_db_connection( node[:gigi][:db_host] )
