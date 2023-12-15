require 'openssl'
require 'base32'


class TOTPGenerator
  attr_reader :key, :hash_algorithm, :t0, :time_step

  def initialize(args)
    @key = args[:key]
    @hash_algorithm = args[:hash_algorithm] || 'sha1'
    @t0 = args[:t0] || 0
    @time_step = args[:time_step] || 30
  end

  def totp()
    counter = (Time.now.to_i - t0) / time_step
    hash = OpenSSL::HMAC.digest(hash_algorithm, key, int_to_bytes(counter)).bytes
    offset = hash.last & 0x0f
    bin_code = ((hash[offset] & 0x7f) << 24) |
               ((hash[offset + 1] & 0xff) << 16) |
               ((hash[offset + 2] & 0xff) << 8) |
               (hash[offset + 3] & 0xff)
    (bin_code % 1_000_000).to_s.rjust(6, '0')
  end

  def generate_every_time_step
    loop do
      puts totp
      sleep(time_step - Time.now.to_i % time_step)
    end
  end

  private
    def int_to_bytes(int)
      result = []
      until int == 0
        result << (int & 0xFF).chr
        int >>= 8
      end
      result.reverse.join.rjust(8, 0.chr)
    end
end

secret_str = open('totp_secret', 'r') do |f|
  f.read()
end
secret = Base32.decode(secret_str.chomp)
TOTPGenerator.new(key: secret).generate_every_time_step

