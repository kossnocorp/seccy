-- Run with lua pkgs/fnox/test.lua (also compatible with LuaJIT).
local calls = {}
local response = {}
local success = true
package.preload["fnox.cmd"] = function()
  return { run = function(argv, options)
    calls[#calls + 1] = { argv = argv, options = options }
    return { ok = success, stdout = "response", stderr = "must not be echoed" }
  end }
end
package.preload["fnox.json"] = function()
  return { decode = function(value)
    assert(value == "response")
    return response
  end }
end
package.preload["fnox.base64"] = function()
  return { decode = function(value)
    assert(value == "encoded")
    return "secret\n\n"
  end }
end

local provider = dofile("pkgs/fnox/provider.lua")
local ctx = { options = { key = "secrets", bin = "/Applications/Seccy.app/Contents/MacOS/seccy", config = "/a path/seccy.toml", socket = "/a path/secrets.sock" } }
response = { ok = true, value = "ciphertext" }
assert(provider.encrypt(ctx, "secret\n\n") == "ciphertext")
assert(calls[1].options.stdin == "secret\n\n")
assert(table.concat(calls[1].argv, "|") == ctx.options.bin .. "|--json|--config|/a path/seccy.toml|encrypt|secrets")

response = { ok = true, value_base64 = "encoded" }
assert(provider.get(ctx, "ciphertext") == "secret\n\n")
assert(calls[2].options.stdin == "ciphertext")
assert(table.concat(calls[2].argv, "|"):find("|decrypt|secrets|--socket|/a path/secrets.sock", 1, true))
local values = provider.get_batch(ctx, { "one", "two" })
assert(values.one == "secret\n\n" and values.two == "secret\n\n")
assert(calls[3].options.stdin == "one" and calls[4].options.stdin == "two")

response = { ok = true }
provider.test(ctx)
assert(calls[5].argv[5] == "crypto-check")
assert(calls[5].options.stdin == "")
success = false
response = { ok = false, error = "authorization cancelled" }
local ok, err = pcall(provider.get, ctx, "ciphertext")
assert(not ok and err:find("authorization cancelled", 1, true))
assert(not err:find("must not be echoed", 1, true))
assert(not pcall(provider.get, { options = {} }, "ciphertext"))
print("fnox adapter tests passed")
