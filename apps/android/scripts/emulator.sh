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
# A fresh fake server: full_run.py ends by recovering the account, which
# gives it a new master password and Secret Key.
kill $server
python3 apps/android/scripts/mock_server.py apk-test/fixture.json 8787 > mock-autofill.log 2>&1 &
server=$!
sleep 2
python3 apps/android/scripts/autofill_run.py apk-test/keyless-mock.apk apk-test/formtest.apk apk-test/fixture.json writes.jsonl || full=1
kill $server
if [ $(( smoke || full )) -ne 0 ]; then
  # What the system said (a process ended, a crash...), for the CI to publish.
  mkdir -p captures
  adb logcat -d -v time > captures/logcat.txt 2>&1
fi
exit $(( smoke || full ))
