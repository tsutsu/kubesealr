# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'base64'

require 'openssl/oaep'

require 'kubeseal/version'

class Kubeseal
  DEFAULT_KEY_FETCHER = lambda do |_|
    raise NotImplementedError, "no cluster key-fetcher passed"
  end

  def initialize(key_fetcher: nil, resealer: nil)
    @cluster_sealer_key_fetcher = key_fetcher || DEFAULT_KEY_FETCHER
    @cluster_sealer_resealer = resealer
  end

  def cluster_sealer_public_key
    @cluster_sealer_public_key ||= @cluster_sealer_key_fetcher.call(:public_key)
  end

  def cluster_sealer_private_keys
    @cluster_sealer_private_keys ||= @cluster_sealer_key_fetcher.call(:private_keys)
  end

  AED_IV = ("\x00" * 12).freeze
  private_constant :AED_IV

  def seal_and_wrap(secret_rc, scope: :strict)
    rc_name = secret_rc.dig('metadata', 'name')
    rc_namespace = secret_rc.dig('metadata', 'namespace')
    rc_type = secret_rc['type'] || 'Opaque'
    scope_label = label_for(scope, rc_namespace, rc_name)

    raw_data =
      if secret_rc.has_key?('data')
        unarmor(secret_rc['data'])
      elsif secret_rc.has_key?('stringData')
        secret_rc['stringData']
      else
        {}
      end

    encrypted_data = raw_data.map do |key, plaintext|
      ciphertext = seal(plaintext, scope_label)
      [key, ciphertext]
    end.to_h

    secret_type = secret_rc['type'] || 'Opaque'

    sealed_secret_rc =
      build_sealed_secret_rc(
        rc_namespace,
        rc_name,
        secret_type,
        armor(encrypted_data)
      )

    patch_with_scope(sealed_secret_rc, scope)
  end

  def unwrap_and_unseal(sealed_secret_rc, armor: true)
    rc_name = sealed_secret_rc.dig('metadata', 'name')
    rc_namespace = sealed_secret_rc.dig('metadata', 'namespace')
    rc_type = sealed_secret_rc['type'] || 'Opaque'

    scope = scope_from_annotations(sealed_secret_rc.dig('metadata', 'annotations'))
    scope_label = label_for(scope, rc_namespace, rc_name)

    # decode data if encoded
    encrypted_data = unarmor(sealed_secret_rc.dig('spec', 'encryptedData'))

    string_data = encrypted_data.map do |key, ciphertext|
      plaintext = unseal(ciphertext, scope_label)
      [key, plaintext]
    end.to_h

    merge_part =
      if armor
        {'data' => armor(string_data)}
      else
        {'stringData' => string_data}
      end

    secret_type = sealed_secret_rc.dig('spec', 'template', 'type') || 'Opaque'

    build_secret_rc(
      rc_namespace,
      rc_name,
      secret_type,
      merge_part
    )
  end

  def seal(plaintext, scope_label)
    cs_pubkey = self.cluster_sealer_public_key

    session_key = SecureRandom.bytes(32)

    session_key_enc =
      cs_pubkey.public_encrypt_oaep(
        session_key,
        scope_label,
        OpenSSL::Digest::SHA256
      )

    aed_cipher = OpenSSL::Cipher.new("AES-256-GCM").encrypt
    aed_cipher.key = session_key
    aed_cipher.iv = AED_IV
    aed_cipher.auth_data = ""

    payload_enc =
      aed_cipher.update(plaintext) +
      aed_cipher.final +
      aed_cipher.auth_tag

    ciphertext_parts = [
      session_key_enc.length,
      session_key_enc,
      payload_enc
    ]

    ciphertext_parts.pack('S>A*A*')
  end

  def unseal(ciphertext, scope_label)
    cs_privkeys_to_try = self.cluster_sealer_private_keys.dup

    session_key_enc_len, ciphertext = ciphertext.unpack('S>A*')
    session_key_enc, ciphertext = ciphertext.unpack("A#{session_key_enc_len}A*")

    session_key = nil
    until session_key or cs_privkeys_to_try.empty?
      begin
        try_privkey = cs_privkeys_to_try.shift
        session_key = try_privkey.private_decrypt_oaep(
          session_key_enc,
          scope_label,
          OpenSSL::Digest::SHA256
        )
      rescue OpenSSL::PKey::RSAError => e
      end
    end

    unless session_key
      raise RuntimeError, "no keys from cluster were applicable to decrypting payload"
    end

    aed_decipher = OpenSSL::Cipher.new("AES-256-GCM").decrypt
    aed_decipher.key = session_key
    aed_decipher.iv = AED_IV

    auth_tag_len = 16
    auth_tag   = ciphertext[-auth_tag_len .. -1]
    ciphertext = ciphertext[0 ... -auth_tag_len]

    aed_decipher.auth_tag = auth_tag
    aed_decipher.auth_data = ""

    plaintext =
      aed_decipher.update(ciphertext) +
      aed_decipher.final

    plaintext
  end

  def reseal(...)
    if @cluster_sealer_resealer
      reseal_serverside(...)
    else
      reseal_clientside(...)
    end
  end

  def reseal_clientside(ciphertext, scope_label)
    plaintext = unseal(ciphertext, scope_label)
    seal(plaintext, scope_label)
  end

  def reseal_serverside(ciphertext, scope_label)
    rc_namespace, rc_name, scope =
      case scope_label.split('/', 2)
      in []
        ["dummy", "dummy", :"cluster-wide"]
      in [ns]
        [ns, "dummy", :"namespace-wide"]
      in [ns, name]
        [ns, name, :strict]
      end

    rc = build_sealed_secret_rc(
      rc_namespace,
      rc_name,
      'Opaque',
      armor({'dummy' => ciphertext}, strict: true)
    )
    rc = patch_with_scope(rc, scope)

    resealed_rc = reseal_wrapped_serverside(rc)

    Base64.decode64(resealed_rc.dig('spec', 'encryptedData', 'dummy'))
  end

  def reseal_wrapped_serverside(sealed_secret_rc)
    YAML.load(@cluster_sealer_resealer.call(sealed_secret_rc.to_yaml))
  end

  private
  def label_for(scope, rc_namespace, rc_name)
    case scope
    in :strict
      "#{rc_namespace}/#{rc_name}"
    in :"namespace-wide"
      rc_namespace
    in :"cluster-wide"
      ""
    end
  end

  CLUSTER_WIDE_ANNOT = 'sealedsecrets.bitnami.com/cluster-wide'.freeze
  private_constant :CLUSTER_WIDE_ANNOT

  NAMESPACE_WIDE_ANNOT = 'sealedsecrets.bitnami.com/namespace-wide'.freeze
  private_constant :NAMESPACE_WIDE_ANNOT

  private
  def scope_from_annotations(annotations)
    annotations ||= {}

    if annotations[CLUSTER_WIDE_ANNOT] == 'true'
      :"cluster-wide"
    elsif annotations[NAMESPACE_WIDE_ANNOT] == 'true'
      :"namespace-wide"
    else
      :strict
    end
  end

  private
  def build_secret_rc(rc_namespace, rc_name, secret_type, data_part)
    {
      'apiVersion' => 'v1',
      'kind' => 'Secret',
      'metadata' => {
        'namespace' => rc_namespace,
        'name' => rc_name
      },
      'type' => secret_type
    }.merge(data_part)
  end

  private
  def build_sealed_secret_rc(rc_namespace, rc_name, secret_type, encrypted_data)
    {
      'apiVersion' => 'bitnami.com/v1alpha1',
      'kind' => 'SealedSecret',
      'metadata' => {
        'namespace' => rc_namespace,
        'name' => rc_name
      },
      'spec' => {
        'template' => {
          'type' => secret_type,
        },
        'encryptedData' => encrypted_data
      }
    }
  end

  private
  def patch_with_scope(sealed_secret_rc, scope)
    case scope
    in :strict
      sealed_secret_rc
    in :"namespace-wide"
      sealed_secret_rc['metadata'] ||= {}
      sealed_secret_rc['metadata']['annotations'] ||= {}
      sealed_secret_rc['metadata']['annotations'][NAMESPACE_WIDE_ANNOT] = "true"
      sealed_secret_rc
    in :"cluster-wide"
      sealed_secret_rc['metadata'] ||= {}
      sealed_secret_rc['metadata']['annotations'] ||= {}
      sealed_secret_rc['metadata']['annotations'][CLUSTER_WIDE_ANNOT] = "true"
      sealed_secret_rc
    end
  end

  def armor(h, strict: false)
    if strict
      (h || {}).map{ |k, v| [k, Base64.strict_encode64(v)] }.to_h
    else
      (h || {}).map{ |k, v| [k, Base64.encode64(v)] }.to_h
    end
  end

  def unarmor(h)
    (h || {}).map{ |k, v| [k, Base64.decode64(v)] }.to_h
  end
end

