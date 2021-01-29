require 'spec_helper'

describe 'ufw::limit', type: :define do
  on_supported_os.each do |os, facts|
    context "on #{os}" do
      let(:facts) { facts }
      let(:title) { 'foo' }

      let(:pre_condition) { 'include ufw' }

      context 'basic operation' do
        it do
          is_expected.to contain_exec('ufw limit foo/tcp')
            .with_command('ufw limit foo/tcp')
            .with_unless("ufw status | grep -qE '^foo/tcp +LIMIT +Anywhere'")
        end
      end

      context 'specifying proto' do
        let(:params) { { proto: 'udp' } }

        it do
          is_expected.to contain_exec('ufw limit foo/udp')
            .with_command('ufw limit foo/udp')
            .with_unless("ufw status | grep -qE '^foo/udp +LIMIT +Anywhere'")
        end
      end
    end
  end
end
