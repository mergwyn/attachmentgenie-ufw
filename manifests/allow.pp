# @summary Create allow rule
#
# @example Allow port 22 (sh)
#   ufw::allow { 'allow-ssh-from-all':
#     port => '22',
#   }
#
# @param direction
#   Traffic direction
# @param ensure
#   Enable of disable rule. default:
# @param from
#   Ip address to allow access from.
# @param ip
#   Ip address to allow access to. default:
# @param port
#   Port to act on.
# @param proto
#   Protocol to use.
#
define ufw::allow(
  Enum['IN','OUT']                         $direction ='IN',
  Enum['absent','present']                 $ensure ='present',
  Variant[Enum['any'],Stdlib::IP::Address] $from = 'any',
  Variant[Enum['any'],Stdlib::IP::Address] $ip = $facts['networking']['ip'],
  Variant[Enum['all'],Stdlib::Port]        $port = 'all',
  Enum[ 'tcp','udp','any']                 $proto = 'tcp',
) {
  $dir = $direction ? {
    'out'   => 'OUT',
    default => ''
  }

  $ipadr = $ip

  $ipver = is_ipv6_address($ipadr) ? {
    true    => 'v6',
    default => 'v4',
  }

  $ipadr_match = $ipadr ? {
    'any'   => $ipver ? {
      'v4' => 'Anywhere',
      'v6' => 'Anywhere \(v6\)',
    },
    default => $ipadr,
  }

  $from_match = $from ? {
    'any'   => $ipver ? {
      'v4' => 'Anywhere',
      'v6' => 'Anywhere \(v6\)',
    },
    default => $from,
  }

  $proto_match = $proto ? {
    'any'   => '',
    default => "/${proto}",
  }

  $from_proto_match = $from ? {
    'any'   => '',
    default => $proto_match,
  }

  $grep_existing_rule = "${ipadr}:${port}" ? {
    'any:all'    => "grep -qE ' +ALLOW ${dir} +${from_match}$'",
    /[0-9]:all$/ => "grep -qE '^${ipadr}${proto_match} +ALLOW +${from_match}${from_proto_match}$'",
    /^any:[0-9]/ => "grep -qE '^${port}${proto_match} +ALLOW +${from_match}$'",
    default      => "grep -qE '^${ipadr} ${port}${proto_match} +ALLOW +${from_match}$'",
  }

  $rule = $port ? {
    'all'   => "allow ${dir} proto ${proto} from ${from} to ${ipadr}",
    default => "allow ${dir} proto ${proto} from ${from} to ${ipadr} port ${port}",
  }

  if $ensure == 'absent' {
    $command = "ufw delete ${rule}"
    $onlyif = "ufw status | ${grep_existing_rule}"

    exec { "ufw-delete-${proto}-from-${from}-to-${ipadr}-port-${port}":
      command  => $command,
      path     => '/usr/sbin:/bin:/usr/bin',
      provider => 'posix',
      onlyif   => $onlyif,
      require  => Exec['ufw-default-deny'],
      before   => Exec['ufw-enable'],
    }
  }
  else {
    $command = "ufw ${rule}"
    $unless  = "${ipadr}:${port}" ? {
      'any:all'    => "ufw status | grep -qE ' +ALLOW +${from_match}${proto_match}$'",
      #'any:all'    => "ufw status | grep -qE ' +ALLOW ${dir} +${from_match}( +.*)?$'",
      /[0-9]:all$/ => "ufw status | grep -qE '^${ipadr_match}${proto_match} +ALLOW +${from_match}${from_proto_match}( +.*)?$'",
      /^any:[0-9]/ => "ufw status | grep -qE '^${port}${proto_match} +ALLOW +${from_match}( +.*)?$'",
      default      => "ufw status | grep -qE '^${ipadr_match} ${port}${proto_match} +ALLOW +${from_match}( +.*)?$'",
    }

  exec { "ufw-allow-${direction}-${proto}-from-${from}-to-${ipadr}-port-${port}":
      command  => $command,
      path     => '/usr/sbin:/bin:/usr/bin',
      provider => 'posix',
      unless   => $unless,
      require  => Exec['ufw-default-deny'],
      before   => Exec['ufw-enable'],
    }
  }
}
