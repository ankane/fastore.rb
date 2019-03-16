require "ffi"

class IntPtr < FFI::Struct
  layout :value, :int
end

class OreParams < FFI::Struct
  layout :initialized, :bool,
         :nbits, :uint32_t,
         :out_len, :uint32_t
end

class OreSecretKey < FFI::Struct
  layout :initialized, :bool,
         :key, [:uchar, 256],
         :params, OreParams
end

class OreCiphertext < FFI::Struct
  layout :initialized, :bool,
         :buf, :pointer,
         :params, OreParams
end

module FastORE
  extend FFI::Library
  ffi_lib "c"
  ffi_lib "./ore.so"
  attach_function :init_ore_params, [OreParams, :uint32_t, :uint32_t], :int
  attach_function :ore_setup, [OreSecretKey, OreParams], :int
  attach_function :ore_cleanup, [OreSecretKey], :int
  attach_function :ore_encrypt_ui, [OreCiphertext, OreSecretKey, :uint64_t], :int
  attach_function :ore_compare, [IntPtr, OreCiphertext, OreCiphertext], :int
  attach_function :init_ore_ciphertext, [OreCiphertext, OreParams], :int
  attach_function :clear_ore_ciphertext, [OreCiphertext], :int
  attach_function :ore_ciphertext_size, [OreParams], :int
end

def err_check(ret)
  if ret != 0
    puts "ERROR"
    exit(1)
  end
end

# no confidence this is correct
def print_ciphertext(n1, n2, ctxt1, ctxt2, params)
  size = FastORE.ore_ciphertext_size(params)
  ciphertext1 = ctxt1[:buf].read_string(size)
  ciphertext2 = ctxt2[:buf].read_string(size)
  require "base64"
  puts "n1: #{n1}"
  puts Base64.strict_encode64(ciphertext1)
  puts "n2: #{n2}"
  puts Base64.strict_encode64(ciphertext2)
  puts
end

def check_ore
  nbits = 31
  out_blk_len = 8 # rand(30) + 2

  n1 = rand(2**31)
  n2 = rand(2**31)

  cmp = n1 < n2 ? -1 : 1
  if n1 == n2
    cmp = 0
  end

  params = OreParams.new
  err_check FastORE.init_ore_params(params, nbits, out_blk_len)

  sk = OreSecretKey.new
  # TODO initialize directly with specific key
  # sk[:initialized] = true
  # sk[:key] =
  # sk[:params] = params
  err_check FastORE.ore_setup(sk, params)

  ctxt1 = OreCiphertext.new
  err_check FastORE.init_ore_ciphertext(ctxt1, params)

  ctxt2 = OreCiphertext.new
  err_check FastORE.init_ore_ciphertext(ctxt2, params)

  err_check FastORE.ore_encrypt_ui(ctxt1, sk, n1)
  err_check FastORE.ore_encrypt_ui(ctxt2, sk, n2)

  print_ciphertext(n1, n2, ctxt1, ctxt2, params)

  ret = 0

  res1 = IntPtr.new
  res2 = IntPtr.new
  res3 = IntPtr.new
  res4 = IntPtr.new

  err_check FastORE.ore_compare(res1, ctxt1, ctxt1)
  err_check FastORE.ore_compare(res2, ctxt1, ctxt2)
  err_check FastORE.ore_compare(res3, ctxt2, ctxt1)
  err_check FastORE.ore_compare(res4, ctxt2, ctxt2)

  if res1[:value] == 0 && res2[:value] == cmp && res3[:value] == (-1 * cmp) && res4[:value] == 0
    ret = 0
  else
    ret = -1
  end

  err_check FastORE.clear_ore_ciphertext(ctxt1)
  err_check FastORE.clear_ore_ciphertext(ctxt2)
  err_check FastORE.ore_cleanup(sk)

  ret
end

200.times do
  if check_ore != 0
    puts "FAIL"
    exit(1)
  end
end

puts "PASS"
