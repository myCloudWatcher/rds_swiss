aws_swiss node[:aws_swiss][:security_group] do
  aws_access_key_id     node[:aws_swiss][:aws_access_key_id]
  aws_secret_access_key node[:aws_swiss][:aws_secret_access_key]
  port                  node[:aws_swiss][:port]     # May be nil
  enable                true
  fallback_group        node[:aws_swiss][:fallback_group] # May be nil
  dbhost                node[:gigi][:db_host]
end
