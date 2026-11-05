local cmd = require("fnox.cmd")
local json = require("fnox.json")
local base64 = require("fnox.base64")

local function invoke(ctx, operation, input)
  local options = ctx.options
  if not options.key or options.key == "" then
    error("seccy provider requires options.key")
  end
  local argv = { options.bin or "seccy", "--json" }
  table.insert(argv, operation)
  table.insert(argv, options.key)
  if options.socket and operation ~= "encrypt" then
    table.insert(argv, "--socket")
    table.insert(argv, options.socket)
  end
  local result = cmd.run(argv, { stdin = input or "" })
  local parsed, response = pcall(json.decode, result.stdout)
  if not parsed or type(response) ~= "table" then
    error("seccy returned an invalid response; check the signed executable and plugin versions")
  end
  if not result.ok or response.ok ~= true then
    error(response.error or "seccy operation failed")
  end
  return response
end

local function get(ctx, ref)
  local response = invoke(ctx, "decrypt", ref)
  if type(response.value_base64) ~= "string" then
    error("seccy returned no decrypted value")
  end
  return base64.decode(response.value_base64)
end

return {
  encrypt = function(ctx, value)
    local response = invoke(ctx, "encrypt", value)
    if type(response.value) ~= "string" then
      error("seccy returned no ciphertext")
    end
    return response.value
  end,
  get = get,
  -- Avoid fnox's parallel lookups competing for biometric prompts.
  -- Each value still requires its own private-key authorization.
  get_batch = function(ctx, refs)
    local values = {}
    for _, ref in ipairs(refs) do
      values[ref] = get(ctx, ref)
    end
    return values
  end,
  test = function(ctx)
    invoke(ctx, "crypto-check")
  end,
}
