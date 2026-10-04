key = OpenSSL::PKey::RSA.new(2048)
ec = OpenSSL::PKey::EC.generate('prime256v1')
