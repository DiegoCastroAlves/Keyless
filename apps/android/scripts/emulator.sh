#!/usr/bin/env bash
# CI, on the emulator: the real APK without an account (smoke.py), then the
# test build end to end against the fake server (full_run.py).
set -u
python3 apps/android/scripts/smoke.py apk/keyless.apk
smoke=$?
python3 apps/android/scripts/mock_server.py apk-test/fixture.json 8787 > mock.log 2>&1 &
server=$!
sleep 2
adb uninstall io.github.diegocastroalves.keyless > /dev/null 2>&1
chmod +x apk-test/requester 2>/dev/null
python3 apps/android/scripts/full_run.py apk-test/keyless-mock.apk apk-test/formtest.apk apk-test/fixture.json writes.jsonl apk-test/requester
full=$?
kill $server
exit $(( smoke || full ))
