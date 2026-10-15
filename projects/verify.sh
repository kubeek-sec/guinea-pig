#!/usr/bin/env bash
# Build every projects/<lang>/{app,app-patched} image, run it, and exercise the
# whole API over HTTP. Exits non-zero if any application fails a check.
#
#   projects/verify.sh              # all languages, app and app-patched
#   projects/verify.sh go rust      # only these languages
#   VARIANTS="app" projects/verify.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LANGUAGES=("$@")
if [ ${#LANGUAGES[@]} -eq 0 ]; then
    mapfile -t LANGUAGES < <(cd "$ROOT/projects" && find . -mindepth 1 -maxdepth 1 -type d \
        -exec test -e '{}/app/Dockerfile' \; -print | sed 's|^\./||' | sort)
fi
read -r -a VARIANT_LIST <<< "${VARIANTS:-app app-patched}"

KEY="verification-instance-key-long-enough-for-hs256"
PASS=0
FAIL=0
FAILED_NAMES=()

# First value of a JSON string field, whatever the key order of the encoder.
first_field() {
    grep -o "\"$1\":\"[^\"]*\"" | head -1 | sed "s/^\"$1\":\"//; s/\"$//"
}

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# check <label> <expected> <actual>
check() {
    if [ "$2" = "$3" ]; then
        printf '    %-26s %s\n' "$1" "ok"
    else
        printf '    %-26s expected %s, got %s\n' "$1" "$2" "$3"
        CASE_OK=0
    fi
}

verify_one() {
    local lang="$1" variant="$2"
    local dir="$ROOT/projects/$lang/$variant"
    local tag="guinea-pig/$lang-$variant"
    CASE_OK=1

    echo "== $lang/$variant"
    if ! docker build -q -t "$tag" "$dir" >/dev/null 2>"$ROOT/.verify-build.log"; then
        echo "    build failed:"
        tail -5 "$ROOT/.verify-build.log" | sed 's/^/      /'
        return 1
    fi

    local port cid
    port="$(free_port)"
    cid="$(docker run -d --rm -p "127.0.0.1:$port:8000" -e "TOOLSHED_TOKEN_KEY=$KEY" "$tag")" || return 1
    trap 'docker rm -f "$cid" >/dev/null 2>&1' RETURN

    local base="http://127.0.0.1:$port"
    local up=0
    for _ in $(seq 1 60); do
        if curl -fsS "$base/healthz" >/dev/null 2>&1; then up=1; break; fi
        sleep 1
    done
    if [ "$up" -ne 1 ]; then
        echo "    did not become healthy; last logs:"
        docker logs "$cid" 2>&1 | tail -5 | sed 's/^/      /'
        return 1
    fi

    local code
    check "healthz version" "1.4.2" \
        "$(curl -s "$base/healthz" | first_field version)"
    check "home page" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$base/")"
    check "openapi document" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$base/openapi.yml")"
    check "tools sorted" "Heat gun" \
        "$(curl -s "$base/api/tools?sort=daily_rate" | first_field name)"
    check "unknown sort column" "400" \
        "$(curl -s -o /dev/null -w '%{http_code}' "$base/api/tools?sort=oops")"
    check "search hits" "2" \
        "$(curl -s "$base/api/tools/search?q=saw" | grep -o '"id"' | wc -l | tr -d ' ')"
    check "one tool" "Circular saw" \
        "$(curl -s "$base/api/tools/1" | first_field name)"
    check "unknown tool" "404" "$(curl -s -o /dev/null -w '%{http_code}' "$base/api/tools/9999")"

    local token
    token="$(curl -s -X POST "$base/api/session" -H 'Content-Type: application/json' \
        -d '{"email":"jun@toolshed.example","password":"sawdust-season"}' | first_field token)"
    check "session issued" "yes" "$([ -n "$token" ] && echo yes || echo no)"
    check "bad credentials" "401" "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        "$base/api/session" -H 'Content-Type: application/json' \
        -d '{"email":"jun@toolshed.example","password":"wrong"}')"

    local auth="Authorization: Bearer $token"
    check "signed-in member" "jun@toolshed.example" \
        "$(curl -s -H "$auth" "$base/api/members/me" | first_field email)"
    check "password withheld" "0" \
        "$(curl -s -H "$auth" "$base/api/members/me" | grep -c '"password"')"
    check "member role refused" "403" \
        "$(curl -s -o /dev/null -w '%{http_code}' -H "$auth" "$base/api/members/1")"
    check "no token" "401" "$(curl -s -o /dev/null -w '%{http_code}' "$base/api/rentals")"
    check "forged token" "401" \
        "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer a.b.c' "$base/api/rentals")"

    local staff_token
    staff_token="$(curl -s -X POST "$base/api/session" -H 'Content-Type: application/json' \
        -d '{"email":"ada@toolshed.example","password":"workshop-keeper"}' | first_field token)"
    check "staff reads a member" "200" "$(curl -s -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $staff_token" "$base/api/members/2")"

    check "take a tool out" "201" "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        "$base/api/rentals" -H "$auth" -H 'Content-Type: application/json' \
        -d '{"tool_id":1,"days":3,"notes":"for the deck boards"}')"
    check "tool now out" "409" "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        "$base/api/rentals" -H "$auth" -H 'Content-Type: application/json' -d '{"tool_id":1}')"
    check "own rentals listed" "1" \
        "$(curl -s -H "$auth" "$base/api/rentals" | grep -o '"tool_id"' | wc -l | tr -d ' ')"
    check "bring it back" "200" "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        "$base/api/rentals/1/return" -H "$auth")"
    check "someone else's rental" "404" "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        "$base/api/rentals/1/return" -H "Authorization: Bearer $staff_token")"

    local photo name
    photo="$(mktemp --suffix=.png)"
    printf 'not really an image' > "$photo"
    name="$(curl -s -X POST "$base/api/photos" -H "$auth" -F "photo=@$photo" | first_field name)"
    check "photo stored" "yes" "$([ -n "$name" ] && echo yes || echo no)"
    if [ -n "$name" ]; then
        check "photo content type" "image/png" \
            "$(curl -s -D- -o /dev/null "$base/api/photos/$name" \
               | tr -d '\r' | sed -n 's/^[Cc]ontent-[Tt]ype: *//p' | head -1)"
        check "photo nosniff" "1" \
            "$(curl -s -D- -o /dev/null "$base/api/photos/$name" | grep -ci 'nosniff')"
    fi
    local text
    text="$(mktemp --suffix=.php)"
    printf 'plain text' > "$text"
    check "other type refused" "400" "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        "$base/api/photos" -H "$auth" -F "photo=@$text")"
    check "unknown photo" "404" \
        "$(curl -s -o /dev/null -w '%{http_code}' "$base/api/photos/none.png")"
    rm -f "$photo" "$text"

    return $((1 - CASE_OK))
}

for lang in "${LANGUAGES[@]}"; do
    for variant in "${VARIANT_LIST[@]}"; do
        if verify_one "$lang" "$variant"; then
            PASS=$((PASS + 1))
        else
            FAIL=$((FAIL + 1))
            FAILED_NAMES+=("$lang/$variant")
        fi
    done
done

rm -f "$ROOT/.verify-build.log"
echo
echo "passed: $PASS   failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
    printf 'failing: %s\n' "${FAILED_NAMES[*]}"
    exit 1
fi
