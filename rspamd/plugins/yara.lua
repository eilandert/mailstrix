--[[
yara.lua — rspamd plugin that scans a message (and optionally each MIME part)
against a set of YARA rules through the yarad HTTP backend.

Why a backend instead of a native module:
  * rspamd has no native YARA module (as of 4.1.0; upstream feature is still an
    open request). libyara is a CGO dependency that would block the worker event
    loop if run in-process.
  * yarad scans out-of-process and answers over HTTP, so this plugin stays fully
    async (rspamd_http) and libyara never enters the rspamd image.

yarad returns JSON:
  { "matches": [ { "rule": "<name>", "namespace": "<file>", "tags": [..], "meta": {..} }, ... ] }

Each matched rule is classified (see classify()) into one scoring-tier symbol —
YARA_MALWARE / YARA_EXPLOIT / YARA_PHISHING / YARA_SUSPICIOUS, or YARA for an
uncategorized hit — with the matched rules as that symbol's options, shown as
"rule (source-file.yar)" (traceable, and actionable by force_actions/multimap).
URLhaus malware-URL hits go to URLHAUS_MALWARE_URL. Per-tier weights live in
groups.conf (group "YARA").

Scope is configurable (scan_message / scan_parts): the full rfc822 message,
each attachment part, or both.
--]]

local rspamd_logger = require "rspamd_logger"
local rspamd_http = require "rspamd_http"
local lua_util = require "lua_util"
local N = "yara"

-- Defaults; overridden by the matching section in local.d/yara.conf.
local settings = {
  url = "http://127.0.0.1:8079/scan",
  token = "",                  -- shared secret; must equal yarad's YARAD_TOKEN
  token_file = "",             -- path to a file holding the token (preferred over
                               -- inline `token`; keeps the secret out of config)
  -- This must cover yarad's worst-case response: the time to acquire a scan slot
  -- (YARAD_BACKEND_TIMEOUT) PLUS the scan itself (YARAD_SCAN_TIMEOUT). yarad's
  -- defaults are intentionally aligned to fit this: 1s queue + 8s scan = 9s,
  -- leaving a little HTTP/JSON overhead before this 10s client timeout expires.
  -- A plugin timeout below that sum just abandons scans that are still running.
  timeout = 10.0,
  max_size = 8 * 1024 * 1024,  -- don't ship bodies larger than this to yarad
  -- Scoring tiers. Each matched rule is classified (see classify()) into ONE of
  -- these symbols by its name/source-file/tags/meta.score, so different kinds of
  -- hit score differently in groups.conf instead of one flat weight for every
  -- rule. `symbol` is the default/uncategorized bucket (and the callback symbol).
  symbol            = "YARA",             -- uncategorized rule match (default)
  symbol_malware    = "YARA_MALWARE",     -- malware family / webshell / RAT / APT
  symbol_exploit    = "YARA_EXPLOIT",     -- exploit / CVE / maldoc exploit
  symbol_phishing   = "YARA_PHISHING",    -- phishing kit / phishing document
  symbol_suspicious = "YARA_SUSPICIOUS",  -- heuristic / suspicious / anomaly
  -- Separate symbol for yarad's URLhaus malware-URL hits (rule names start
  -- "URLHAUS_"), so they score independently of YARA rule matches.
  urlhaus_symbol = "URLHAUS_MALWARE_URL",
  -- What to scan. At least one must be true or the plugin does nothing.
  scan_message = true,         -- the whole rfc822 message in one scan
  scan_parts = true,          -- each MIME part (attachment) separately
  -- Only scan parts at/above this many bytes individually (tiny text parts are
  -- already covered by scan_message; skipping them saves round-trips).
  min_part_size = 64,
}

-- post sends buf to yarad and invokes cb(matches) with the decoded rule list
-- (possibly empty). Errors are logged and treated as "no match" (fail-open):
-- a scanner problem must never block mail.
local function post(task, buf, what, cb)
  local function http_cb(err, code, body)
    if err then
      rspamd_logger.errx(task, "yarad request failed (%s): %s", what, err)
      return cb({})
    end
    if code ~= 200 then
      rspamd_logger.errx(task, "yarad returned HTTP %s (%s)", code, what)
      return cb({})
    end
    local ucl = require "ucl"
    local parser = ucl.parser()
    local ok, perr = parser:parse_string(body)
    if not ok then
      rspamd_logger.errx(task, "cannot parse yarad response: %s", perr)
      return cb({})
    end
    local res = parser:get_object()
    if type(res) ~= "table" or type(res.matches) ~= "table" then
      return cb({})
    end
    return cb(res.matches)
  end

  local headers = { ["Content-Type"] = "application/octet-stream" }
  if settings.token and settings.token ~= "" then
    headers["X-YARAD-Token"] = settings.token
  end

  -- rspamd_http.request returns false when it could not even schedule the
  -- request (e.g. bad URL, no resolver). In that case http_cb will NEVER fire, so
  -- without this the per-job callback never runs, `pending` never reaches 0, and
  -- the whole message's collected matches are silently dropped. Fail open here.
  local scheduled = rspamd_http.request({
    task = task,
    url = settings.url,
    body = buf,
    callback = http_cb,
    timeout = settings.timeout,
    method = "POST",
    headers = headers,
  })
  if not scheduled then
    rspamd_logger.errx(task, "yarad request could not be scheduled (%s)", what)
    return cb({})
  end
end

-- classify maps a matched YARA rule to a scoring-tier symbol from its name,
-- source file (namespace), tags and any meta.score. Heuristic and intentionally
-- tunable here (retuning needs only an rspamd reload, no yarad rebuild). The
-- strongest signal wins; anything unrecognised falls back to the default symbol.
local function classify(m)
  local hay = string.lower((m.rule or "") .. " " .. (m.namespace or ""))
  if type(m.tags) == "table" then
    hay = hay .. " " .. string.lower(table.concat(m.tags, " "))
  end
  local function has(...)
    for _, p in ipairs({ ... }) do
      if hay:find(p, 1, true) then return true end
    end
    return false
  end
  -- Exploit / CVE / maldoc exploit (Equation Editor, shellcode, …).
  if has("expl", "cve", "exploit", "equation", "shellcode") then
    return settings.symbol_exploit
  end
  -- Malware family / webshell / hacktool / APT / ransomware / loader / stealer.
  if has("malw", "webshell", "ransom", "backdoor", "trojan", "apt_", "apt-",
         "hktl", "hacktool", "loader", "stealer", "botnet", "dropper", "keylog") then
    return settings.symbol_malware
  end
  -- Phishing kits / phishing documents.
  if has("phish", "_pk_", "phishingkit", "credential") then
    return settings.symbol_phishing
  end
  -- Heuristic / suspicious / anomaly / obfuscation.
  if has("susp", "anomaly", "heuristic", "obfusc") then
    return settings.symbol_suspicious
  end
  -- Fall back to a numeric meta.score where the ruleset provides one (YARA-Forge,
  -- signature-base): high = malware-grade, low = suspicious, else generic.
  local sc = tonumber(m.meta and m.meta.score)
  if sc then
    if sc >= 75 then return settings.symbol_malware end
    if sc < 40 then return settings.symbol_suspicious end
  end
  return settings.symbol
end

local function check_cb(task)
  -- Skip authenticated / outbound mail.
  if task:get_user() then return end

  -- Collect the buffers to scan: the whole message and/or each sizeable part.
  local jobs = {}
  if settings.scan_message then
    local content = task:get_content()
    if content and #content > 0 and #content <= settings.max_size then
      jobs[#jobs + 1] = { buf = content, what = "message" }
    end
  end
  if settings.scan_parts then
    for _, part in ipairs(task:get_parts() or {}) do
      local content = part:get_content()
      if content and #content >= settings.min_part_size and #content <= settings.max_size then
        jobs[#jobs + 1] = { buf = content, what = "part" }
      end
    end
  end
  if #jobs == 0 then return end

  -- Fan out the scans; bucket distinct matches per scoring-tier symbol across all
  -- buffers. Each YARA rule is classified into a tier (malware/exploit/phishing/
  -- suspicious/default) so different hits score differently; URLHAUS_* hits go to
  -- their own symbol. One insert_result per non-empty symbol, after the last
  -- response, with the rule names (or URLs) as that symbol's options.
  local seen = {}
  local buckets = {} -- symbol name -> array of option strings
  local pending = #jobs

  local function add(sym, opt, key)
    if seen[key] then return end
    seen[key] = true
    local b = buckets[sym]
    if not b then
      b = {}
      buckets[sym] = b
    end
    b[#b + 1] = opt
  end

  local function finish()
    pending = pending - 1
    if pending > 0 then return end
    for sym, opts in pairs(buckets) do
      if #opts > 0 then
        task:insert_result(sym, 1.0, opts)
      end
    end
  end

  for _, job in ipairs(jobs) do
    post(task, job.buf, job.what, function(matches)
      for _, m in ipairs(matches) do
        if m.rule then
          if m.rule:sub(1, 8) == "URLHAUS_" then
            -- For URLhaus hits the interesting thing is the malicious URL, not
            -- the (constant) rule name, so show the URL itself as the option;
            -- dedup on the URL so several distinct bad links don't collapse into
            -- one. Append a short tag for the host/deobfuscated variants.
            local url = (type(m.meta) == "table" and m.meta.url) or m.rule
            local tag = ""
            if m.rule:find("_HOST") then tag = tag .. " (host)" end
            if m.rule:find("_DEOBF") then tag = tag .. " (deobf)" end
            add(settings.urlhaus_symbol, url .. tag, "u:" .. url)
          else
            -- Classify into a scoring tier, and show "rule (source-file)" so a
            -- generic rule name (e.g. "http") is traceable to the ruleset that
            -- shipped it. m.namespace is the compiled rule file.
            local sym = classify(m)
            local opt = m.rule
            if m.namespace and m.namespace ~= "" then
              opt = m.rule .. " (" .. m.namespace .. ")"
            end
            add(sym, opt, "y:" .. m.rule)
          end
        end
      end
      finish()
    end)
  end
end

-- Merge user config over defaults.
local opts = rspamd_config:get_all_opt(N)
if opts then
  settings = lua_util.override_defaults(settings, opts)
end

-- Resolve the shared secret. A token_file (Docker secret / 0444 file) wins over
-- an inline token so the secret never has to live in the config. Read at config
-- time only; trailing whitespace/newline is trimmed.
if settings.token_file and settings.token_file ~= "" then
  local f = io.open(settings.token_file, "r")
  if f then
    local t = f:read("*a") or ""
    f:close()
    settings.token = t:gsub("%s+$", "")
  else
    rspamd_logger.errx(rspamd_config, "%s: cannot read token_file %s", N, settings.token_file)
  end
end
if settings.token == "" then
  rspamd_logger.warnx(rspamd_config, "%s: no token set (token/token_file); yarad will refuse all scans", N)
elseif settings.token == "change-me" then
  rspamd_logger.warnx(rspamd_config, "%s: token is the placeholder 'change-me'; set a real shared secret", N)
end

if not settings.scan_message and not settings.scan_parts then
  rspamd_logger.warnx(rspamd_config, "%s: both scan_message and scan_parts are false; plugin disabled", N)
  return
end

local id = rspamd_config:register_symbol({
  name = settings.symbol,
  type = "callback",
  callback = check_cb,
  flags = "empty",
})

-- The tier symbols and the URLhaus symbol are all inserted from the same
-- callback, so register each as a virtual child of the callback symbol: rspamd
-- then knows them (no "unknown symbol" warnings) and they can be scored
-- independently in groups.conf.
for _, s in ipairs({
  settings.symbol_malware,
  settings.symbol_exploit,
  settings.symbol_phishing,
  settings.symbol_suspicious,
  settings.urlhaus_symbol,
}) do
  rspamd_config:register_symbol({ name = s, type = "virtual", parent = id })
end

rspamd_logger.infox(rspamd_config, "%s: registered, backend=%s scan_message=%s scan_parts=%s urlhaus_symbol=%s",
  N, settings.url, settings.scan_message, settings.scan_parts, settings.urlhaus_symbol)
