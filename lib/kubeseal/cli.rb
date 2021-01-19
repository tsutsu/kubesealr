require 'optparse'
require 'yaml'

require 'k8s-ruby'

require 'kubeseal'

class Kubeseal::CLI
  def self.start(argv = ARGV)
    trap('INT'){ Kernel.exit(0) }
    self.new(argv).run
  end

  def initialize(argv = ARGV)
    @k8s_client = K8s::Client.autoconfig

    @mode = :encrypt
    @scope = :strict
    @decrypt_rearmor = true
    self.option_parser.parse(argv)

    @sealer = Kubeseal.new do |fetch_mode|
      case fetch_mode
      in :public_key
        fetch_cluster_sealer_active_public_key
      in :private_keys
        fetch_cluster_sealer_all_private_keys
      end
    end
  end

  def option_parser
    OptionParser.new do |parser|
      parser.banner = "Usage: kubesealr [options]"

      parser.on("-d", "--decrypt", "Unseal sealed secrets (requires k8s User to have get access to secrets in kube-system namespace)") do |t|
        @mode = :decrypt
      end

      parser.on("-a", "--[no-]armor", "Emit base64-armored secrets when unsealing") do |t|
        @decrypt_rearmor = t
      end

      parser.on("-sTYPE", "--scope TYPE", [:strict, :"namespace-wide", :"cluster-wide"],
                "Select scope (strict, namespace-wide, cluster-wide)") do |v|
        @scope = v
      end
    end
  end

  def run
    case @mode
    in :encrypt
      $stdout.puts(seal_stream($stdin.read))
    in :decrypt
      $stdout.puts(unseal_stream($stdin.read))
    end
  end

  private
  def fetch_cluster_sealer_active_public_key
    cert_req_opts = {
      method: 'GET',
      path: '/api/v1/namespaces/kube-system/services/sealed-secrets-controller:8080/proxy/v1/cert.pem'
    }.merge(@k8s_client.transport.request_options)

    cert_resp = @k8s_client.transport.excon.request(cert_req_opts)

    cert_pem_str = cert_resp.body

    cluster_certificate = OpenSSL::X509::Certificate.new(cert_pem_str)

    cluster_certificate.public_key
  end

  private
  def fetch_cluster_sealer_all_private_keys
    privkey_pem_strs =
      @k8s_client.api('v1')
      .resource('secrets', namespace: 'kube-system')
      .list(fieldSelector: {'type' => 'kubernetes.io/tls'})
      .filter{ |r| r.metadata.generateName == 'sealed-secrets-key' }
      .map{ |r| Base64.decode64(r.data['tls.key']) }

    privkey_pem_strs.map{ |pem| OpenSSL::PKey::RSA.new(pem) }
  end

  private
  def seal_stream(secret_yaml_stream)
    YAML.load_stream(secret_yaml_stream).map do |secret_rc|
      @sealer.seal_and_wrap(secret_rc, scope: @scope).to_yaml
    end.join("")
  end

  private
  def unseal_stream(sealed_secret_yaml_stream)
    YAML.load_stream(sealed_secret_yaml_stream).map do |sealed_secret_rc|
      @sealer.unwrap_and_unseal(sealed_secret_rc, armor: @decrypt_rearmor).to_yaml
    end.join("")
  end
end
