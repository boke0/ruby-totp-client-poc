require 'json'

print "key> "

key = gets
key.chomp!

open('totp_secret', 'w') do |f|
  f.puts(key)
end
