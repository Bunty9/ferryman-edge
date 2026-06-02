-- wrk2 harness for ferryman-edge.
--
-- Adds an Authorization: Bearer <JWT> header so the auth path exercises the
-- JWT verifier + cache. The token below is a placeholder — generate a real
-- one signed by certs/jwt-priv.pem before running the throughput bench.

wrk.method  = "GET"
wrk.headers["Authorization"] = "Bearer REPLACE_ME_WITH_RS256_JWT"
wrk.headers["X-Ferryman-Edge-Bench"] = "1"

function response(status, _headers, _body)
    if status >= 400 then
        io.stderr:write(string.format("status=%d\n", status))
    end
end
