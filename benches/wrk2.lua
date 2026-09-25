-- wrk2 harness for ferryman-edge.
--
-- Adds an Authorization: Bearer <JWT> header so the auth path exercises the
-- JWT verifier + cache. Mint a token with:
--   export FERRYMAN_JWT=$(scripts/mint-jwt.sh)
--
-- NOTE: wrk/wrk2 cannot present a TLS client certificate, so this harness
-- only works against a listener that does not require mTLS. For the mTLS
-- reload check use benches/reload.sh.

local token = os.getenv("FERRYMAN_JWT")
if not token or token == "" then
    error("FERRYMAN_JWT is not set; run: export FERRYMAN_JWT=$(scripts/mint-jwt.sh)")
end

wrk.method = "GET"
wrk.headers["Authorization"] = "Bearer " .. token
wrk.headers["X-Ferryman-Edge-Bench"] = "1"

function response(status, _headers, _body)
    if status >= 400 then
        io.stderr:write(string.format("status=%d\n", status))
    end
end
