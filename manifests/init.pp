# @summary Installs and enables Ubuntu's "uncomplicated" firewall.
#
# @note
#   Be careful calling this class alone, it will by default enable ufw
#   and disable all incoming traffic.
#
# @example when declaring the ufw class
#   include ufw
#
# @param allow
#   Set of connections to allow.
# @param deny
#   Set of connections to deny.
# @param deny_outgoing
#   Block out going connections.
# @param forward
#   Behavior for forwards.
# @param limit
#   Hash of connections to limit.
# @param log_level
#   Level to log with.
# @param manage_service
#   Manage the service.
# @param reject
#   Hash of connections to reject.
# @param service_name
#   Name of service to manage.
#
class ufw(
  Hash $allow                                         = undef,
  Hash $deny                                          = undef,
  Boolean $deny_outgoing                              = false,
  Enum['ACCEPT','DROP','REJECT'] $forward             = 'DROP',
  Hash $limit                                         = undef,
  Enum['off','low','medium','high','full'] $log_level = 'low',
  Boolean $manage_service                             = true,
  Hash $reject                                        = undef,
  String $service_name                                = 'ufw',
) {
  Exec {
    path     => '/bin:/sbin:/usr/bin:/usr/sbin',
    provider => 'posix',
  }

  anchor { 'ufw::begin': }
  -> class{ '::ufw::install': }
  -> class{ '::ufw::config': }
  ~> class{ '::ufw::service': }
  -> anchor { 'ufw::end': }

  # Hiera resource creation
  create_resources('::ufw::allow',  $allow)
  create_resources('::ufw::deny', $deny)
  create_resources('::ufw::limit', $limit)
  create_resources('::ufw::reject', $reject)
}
