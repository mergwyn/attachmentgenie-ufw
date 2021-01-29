require 'spec_helper'

describe 'ufw::allow', type: :define do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) { facts }
      let(:title) { 'foo' }
      let(:ip) { facts[:networking]['ip'] }
    
      let(:pre_condition) { 'include ufw' }

      context 'basic operation' do
        let(:params) { { ip: '192.168.42.42' } }
        it do
          is_expected.to contain_exec('ufw-allow-IN-tcp-from-any-to-192.168.42.42-port-all')
            .with_command('ufw allow  proto tcp from any to 192.168.42.42')
            .with_unless("ufw status | grep -qE '^192.168.42.42/tcp +ALLOW +Anywhere( +.*)?$'")
        end
      end

      context 'specifying from address' do
        let(:params) { { from: '192.0.2.42', ip: '192.168.42.42', } }

        it do
          is_expected.to contain_exec('ufw-allow-IN-tcp-from-192.0.2.42-to-192.168.42.42-port-all')
            .with_command('ufw allow  proto tcp from 192.0.2.42 to 192.168.42.42')
            .with_unless("ufw status | grep -qE '^192.168.42.42/tcp +ALLOW +192.0.2.42/tcp( +.*)?$'")
        end
      end

      describe 'specifying to address' do

        context 'from networking::ip fact' do
          it do
            is_expected.to contain_exec("ufw-allow-IN-tcp-from-any-to-#{ip}-port-all")
              .with_command("ufw allow  proto tcp from any to #{ip}")
              .with_unless("ufw status | grep -qE '^#{ip}/tcp +ALLOW +Anywhere( +.*)?$'")
          end
        end

        context 'from $ip parameter' do
          let(:params) { { ip: '192.0.2.68' } }

          it do
            is_expected.to contain_exec('ufw-allow-IN-tcp-from-any-to-192.0.2.68-port-all')
              .with_command('ufw allow  proto tcp from any to 192.0.2.68')
              .with_unless("ufw status | grep -qE '^192.0.2.68/tcp +ALLOW +Anywhere( +.*)?$'")
          end
        end

        context 'from $ip parameter (any protocol)' do
          let(:params) { { ip: '192.0.2.68', proto: 'any', } }

          it do
            is_expected.to contain_exec('ufw-allow-IN-any-from-any-to-192.0.2.68-port-all')
              .with_command('ufw allow  proto any from any to 192.0.2.68')
              .with_unless("ufw status | grep -qE '^192.0.2.68 +ALLOW +Anywhere( +.*)?$'")
          end
        end

        context 'from $ip parameter (ipv6)' do
          let(:params) { { ip: '2a00:1450:4009:80c::1001' } }

          it do
            is_expected.to contain_exec('ufw-allow-IN-tcp-from-any-to-2a00:1450:4009:80c::1001-port-all')
              .with_command('ufw allow  proto tcp from any to 2a00:1450:4009:80c::1001')
              .with_unless("ufw status | grep -qE '^2a00:1450:4009:80c::1001/tcp +ALLOW +Anywhere \\(v6\\)( +.*)?$'")
          end
        end

        context 'from $ip parameter (ipv6, any protocol)' do
          let(:params) { { ip: '2a00:1450:4009:80c::1001', proto: 'any', } }

          it do
            is_expected.to contain_exec('ufw-allow-IN-any-from-any-to-2a00:1450:4009:80c::1001-port-all')
              .with_command('ufw allow  proto any from any to 2a00:1450:4009:80c::1001')
              .with_unless("ufw status | grep -qE '^2a00:1450:4009:80c::1001 +ALLOW +Anywhere \\(v6\\)( +.*)?$'")
          end
        end

        context 'when both $ip and networking::ip are specified' do
          let(:facts) { { networking:{ ip: '192.0.2.67' } } }
          let(:params) { { ip: '192.0.2.68' } }

          it do
            is_expected.to contain_exec('ufw-allow-IN-tcp-from-any-to-192.0.2.68-port-all')
              .with_command('ufw allow  proto tcp from any to 192.0.2.68')
              .with_unless("ufw status | grep -qE '^192.0.2.68/tcp +ALLOW +Anywhere( +.*)?$'")
          end
        end

        context 'when from is a specific ip address' do
          let(:facts) { { networking: { ip: '192.0.2.68'} } }
          let(:params) { { from: '192.0.2.69' } }

          it do
            is_expected.to contain_exec('ufw-allow-IN-tcp-from-192.0.2.69-to-192.0.2.68-port-all')
              .with_command('ufw allow  proto tcp from 192.0.2.69 to 192.0.2.68')
              .with_unless("ufw status | grep -qE '^192.0.2.68/tcp +ALLOW +192.0.2.69/tcp( +.*)?$'")
          end
        end
      end

      context 'specifying port' do
        let(:params) { { port: '8080' } }

        it do
          is_expected.to contain_exec("ufw-allow-IN-tcp-from-any-to-#{ip}-port-8080")
            .with_command("ufw allow  proto tcp from any to #{ip} port 8080")
            .with_unless("ufw status | grep -qE '^#{ip} 8080/tcp +ALLOW +Anywhere( +.*)?$'")
        end
      end

      context 'specifying port for any protocol' do
        let(:params) { { port: '8080', proto: 'any' } }

        it do
          is_expected.to contain_exec("ufw-allow-IN-any-from-any-to-#{ip}-port-8080")
            .with_command("ufw allow  proto any from any to #{ip} port 8080")
            .with_unless("ufw status | grep -qE '^#{ip} 8080 +ALLOW +Anywhere( +.*)?$'")
        end
      end

      context 'with ensure => absent' do
        let(:params) { { ensure: 'absent' } }

        it do
          is_expected.to contain_exec("ufw-delete-tcp-from-any-to-#{ip}-port-all")
            .with_command("ufw delete allow  proto tcp from any to #{ip}")
            .with_onlyif("ufw status | grep -qE '^#{ip}/tcp +ALLOW +Anywhere$'")
        end
      end
    end
  end
end
