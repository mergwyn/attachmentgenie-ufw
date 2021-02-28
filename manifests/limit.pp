# @summary Set rate limit for port
#
# @example Rate limit port 22 (ssh)
#   ufw::limit { '22': }
#
# @param proto
#   Protocol to use
#
define ufw::limit(
  Enum[ 'tcp','udp'] $proto = 'tcp',
) {
  exec { "ufw limit ${name}/${proto}":
    path     => '/usr/sbin:/bin:/usr/bin',
    provider => 'posix',
    unless   => "ufw status | grep -qE '^${name}/${proto} +LIMIT +Anywhere'",
    require  => Exec['ufw-default-deny'],
    before   => Exec['ufw-enable'],
  }
}
