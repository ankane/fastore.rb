require "ffi"

class IntPtr < FFI::Struct
  layout :value, :int
end

class OreBlkParams < FFI::Struct
  layout :initialized, :bool,
         :nbits, :uint32_t,
         :out_blk_len, :uint32_t
end

class OreBlkSecretKey < FFI::Struct
  layout :initialized, :bool,
         :prf_key, [:uchar, 256],
         :prp_key, [:uchar, 256],
         :params, OreBlkParams
end

class OreBlkCiphertext < FFI::Struct
  layout :initialized, :bool,
         :comp_left, :pointer,
         :comp_right, :pointer,
         :params, OreBlkParams
end

module FastORE
  extend FFI::Library
  ffi_lib "c"
  ffi_lib "./ore_blk.so"
  attach_function :init_ore_blk_params, [OreBlkParams, :uint32_t, :uint32_t], :int
  attach_function :ore_blk_setup, [OreBlkSecretKey, OreBlkParams], :int
  attach_function :ore_blk_cleanup, [OreBlkSecretKey], :int
  attach_function :ore_blk_encrypt_ui, [OreBlkCiphertext, OreBlkSecretKey, :uint64_t], :int
  attach_function :ore_blk_compare, [IntPtr, OreBlkCiphertext, OreBlkCiphertext], :int
  attach_function :init_ore_blk_ciphertext, [OreBlkCiphertext, OreBlkParams], :int
  attach_function :clear_ore_blk_ciphertext, [OreBlkCiphertext], :int
  attach_function :ore_blk_ciphertext_size, [OreBlkCiphertext], :int
end

def err_check(ret)
  if ret != 0
    puts "ERROR"
    exit(1)
  end
end

# no confidence this is correct
def print_ciphertext(n1, n2, ctxt1, ctxt2, params)
  size = FastORE.ore_blk_ciphertext_size(params)
  left_ciphertext1 = ctxt1[:comp_left].read_string(size)
  left_ciphertext2 = ctxt2[:comp_left].read_string(size)
  right_ciphertext1 = ctxt1[:comp_right].read_string(size)
  right_ciphertext2 = ctxt2[:comp_right].read_string(size)
  require "base64"
  puts "n1: #{n1}"
  puts Base64.strict_encode64(left_ciphertext1)
  puts Base64.strict_encode64(right_ciphertext1)
  puts "n2: #{n2}"
  puts Base64.strict_encode64(left_ciphertext2)
  puts Base64.strict_encode64(right_ciphertext2)
  puts
end

def check_ore_blk
  nbits = 32
  block_len = 8

  n1 = rand(2**32)
  n2 = rand(2**32)

  cmp = n1 < n2 ? -1 : 1
  if n1 == n2
    cmp = 0
  end

  params = OreBlkParams.new
  err_check FastORE.init_ore_blk_params(params, nbits, block_len)

  sk = OreBlkSecretKey.new
  err_check FastORE.ore_blk_setup(sk, params)

  ctxt1 = OreBlkCiphertext.new
  err_check FastORE.init_ore_blk_ciphertext(ctxt1, params)

  ctxt2 = OreBlkCiphertext.new
  err_check FastORE.init_ore_blk_ciphertext(ctxt2, params)

  err_check FastORE.ore_blk_encrypt_ui(ctxt1, sk, n1)
  err_check FastORE.ore_blk_encrypt_ui(ctxt2, sk, n2)

  print_ciphertext(n1, n2, ctxt1, ctxt2, params)

  ret = 0
  res = IntPtr.new
  err_check FastORE.ore_blk_compare(res, ctxt1, ctxt2)
  if res[:value] != cmp
    ret = -1
  end

  err_check FastORE.clear_ore_blk_ciphertext(ctxt1)
  err_check FastORE.clear_ore_blk_ciphertext(ctxt2)
  err_check FastORE.ore_blk_cleanup(sk)

  ret
end

500.times do
  if check_ore_blk != 0
    puts "FAIL"
    exit(1)
  end
end

puts "PASS"
