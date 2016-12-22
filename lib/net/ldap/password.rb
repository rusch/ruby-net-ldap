require 'digest'
require 'digest'
require 'base64'
require 'securerandom'

class Net::LDAP::Password
  class << self
    @@hash_algos = {}

    def add_hash_algo(type, proc)
      @@hash_algos[type] = proc
    end

    def hash_algos
      @@hash_algos.keys
    end

    # Generate a password-hash suitable for inclusion in an LDAP attribute.
    # Pass a hash type as a symbol (:md5, :sha, :ssha) and a plaintext
    # password. This function will return a hashed representation.
    #
    #--
    # STUB: This is here to fulfill the requirements of an RFC, which
    # one?
    #
    # TODO:
    # * maybe salted-md5
    # * Should we provide sha1 as a synonym for sha1? I vote no because then
    #   should you also provide ssha1 for symmetry?
    #
    def generate(type, str)
      if proc = @@hash_algos[type]
        return proc.call(str)
      end

      raise Net::LDAP::HashTypeUnsupportedError, "Unsupported password-hash type (#{type})"
    end

    def generate_plain(str)
      str
    end

    def generate_md5(str)
      '{MD5}' + Base64.encode64(Digest::MD5.digest(str)).chomp
    end

    def generate_sha(str)
      '{SHA}' + Base64.encode64(Digest::SHA1.digest(str)).chomp
    end

    def generate_ssha(str)
      salt = SecureRandom.random_bytes(16)
      '{SSHA}' + Base64.encode64(Digest::SHA1.digest(str + salt) + salt).chomp
    end

    def generate_ssha512(str)
      salt = SecureRandom.random_bytes(16)
      '{SSHA-512}' + Base64.encode64(Digest::SHA512.digest(str + salt) + salt).chomp
    end

  end

  add_hash_algo(:plain,   method(:generate_plain).to_proc)
  add_hash_algo(:md5,     method(:generate_md5).to_proc)
  add_hash_algo(:sha,     method(:generate_sha).to_proc)
  add_hash_algo(:ssha,    method(:generate_ssha).to_proc)
  add_hash_algo(:ssha512, method(:generate_ssha512).to_proc)

end
