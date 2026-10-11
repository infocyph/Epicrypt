-- wrk executes setup/done in a control Lua state and response in worker states.
-- Only exactly correct HTTP 200 responses are counted toward throughput.
local threads = {}

function setup(thread)
    table.insert(threads, thread)
end

function init(args)
    validated = 0
    invalid = 0
    expected_body = os.getenv("HOST_EXPECTED_BODY")
    if expected_body == nil or expected_body == "" then
        error("HOST_EXPECTED_BODY must contain the independently verified response body")
    end
end

function response(status, headers, body)
    if status == 200 and body == expected_body then
        validated = validated + 1
    else
        invalid = invalid + 1
    end
end

function done(summary, latency, requests)
    local valid = 0
    local bad = 0
    for _, thread in ipairs(threads) do
        valid = valid + (thread:get("validated") or 0)
        bad = bad + (thread:get("invalid") or 0)
    end
    io.write(string.format(
        "EPICRYPT_WRK %d %d %d %d %d %d %d %.0f %.0f %.0f %.0f\n",
        valid, bad, summary.requests, summary.errors.connect,
        summary.errors.read, summary.errors.write, summary.errors.timeout,
        summary.duration, latency:percentile(50), latency:percentile(95),
        latency:percentile(99)
    ))
end
