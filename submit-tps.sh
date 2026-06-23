#!/usr/bin/env bash
set -euo pipefail

TOKEN='eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4QXFNc1VGTW1zS2NnQWxrckpJelBienMybWFvX0tCX3FfZW4tNkwwN0xnIn0.eyJleHAiOjE3ODIxMjg3MjQsImlhdCI6MTc4MjEyODQyNCwiYXV0aF90aW1lIjoxNzgyMTI4MDk0LCJqdGkiOiJvbnJ0YWM6MDlmNmNkNTYtYTQ1ZS03ODYzLTQ5YzMtMGViMzViZjY4YWFiIiwiaXNzIjoiaHR0cHM6Ly9pZHAuZGVmZW5zZXBvaW50LmNvbS9hdXRoL3JlYWxtcy9kZWZlbnNlcG9pbnQiLCJzdWIiOiJmYTM1NGFlYS1iMjJiLTQ2MDYtOWJjMy1iYjMyZjBlMWZlNTUiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJNZW5kQmVuY2htYXJrUGxhdGZvcm0iLCJzaWQiOiI4NTgxM2E5OS0xOWRkLTk0YWQtZWE3ZC0zYzhjZjY1ZTY5NWQiLCJhY3IiOiIwIiwiYWxsb3dlZC1vcmlnaW5zIjpbIioiXSwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYW1lIjoiTHVjYSBBZ3JhIiwicHJlZmVycmVkX3VzZXJuYW1lIjoibHVjYUBkZWZlbnNlcG9pbnQuY29tIiwiZ2l2ZW5fbmFtZSI6Ikx1Y2EiLCJmYW1pbHlfbmFtZSI6IkFncmEiLCJlbWFpbCI6Imx1Y2FAZGVmZW5zZXBvaW50LmNvbSJ9.ijlfBL7UCcxVDZ_ti_YekKIrg_ngH7NSAkkiBX2mleyQxUePbHMbQaHLGFJ2ITJJwbBCgGPXRdFPTlG_59G6bF4RyG6sJ5YPHsX6CANC4EkiVtGnYFEHY78KSZ4gMBCBIkG5ydsc9b0vmTdWqibSVTpsLZyX2FmCRO3aBmV3HR94TS9kML6WbYZNL5UvxZz0CdRnBvb3ynhXjUqfK0nezbA5gSf9FedskA25k3ETA1CD1ugCnq1Cet30p6-b8sLJFHbV5-AtkvNYTbAyzN6two9IUUnfTQ0e2RfY3RIu3ndVh3Qdk5yKNxUeQrjlC-XHKU2G9et5sVMxFoZ7wylheg'
API='https://benchmark-platform.defensepoint.com/api/scan/1561/finding/manually'
BASE='https://github.com/scala-benchmark/spark/blob/stage-2'

submit() {
  curl "$API" \
    -H 'accept: */*' \
    -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -H 'origin: https://benchmark-platform.defensepoint.com' \
    --data-raw "$1"
  echo
}

# CWE-99 — Resource Injection
submit '{"title":"Improper Control of Resource Identifiers (Resource Injection)","description":"The product receives input from an upstream component, but it does not restrict or incorrectly restricts the input before it is used as an identifier for a resource that may be outside the intended sphere of control.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/SupportResource.scala#L83","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/KVUtils.scala#L327","cwes":["CWE-99"],"path":"KVUtils.scala:327"}'

# CWE-470 — Unsafe Reflection
submit '{"title":"Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)","description":"The product uses external input with reflection to select which classes or code to use, but it does not sufficiently prevent the input from selecting improper classes or code.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/OneApplicationResource.scala#L478","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/ui/UIUtils.scala#L874","cwes":["CWE-470"],"path":"UIUtils.scala:874"}'

# CWE-88 — Argument Injection
submit '{"title":"Improper Neutralization of Argument Delimiters in a Command (Argument Injection)","description":"The product constructs a string for a command to be executed by a separate component in another control sphere, but it does not properly delimit the intended arguments, options, or switches within that command string.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/OneApplicationResource.scala#L501","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/OneApplicationResource.scala#L511","cwes":["CWE-88"],"path":"OneApplicationResource.scala:511"}'

# CWE-287 — Improper Authentication
submit '{"title":"Improper Authentication","description":"When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/StagesResource.scala#L350","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/StagesResource.scala#L359","cwes":["CWE-287"],"path":"StagesResource.scala:359"}'

# CWE-347 — Improper Verification of Cryptographic Signature
submit '{"title":"Improper Verification of Cryptographic Signature","description":"The product does not verify, or incorrectly verifies, the cryptographic signature for data.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/ApplicationListResource.scala#L75","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/ApplicationListResource.scala#L82","cwes":["CWE-347"],"path":"ApplicationListResource.scala:82"}'

# CWE-321 — Use of Hard-coded Cryptographic Key
submit '{"title":"Use of Hard-coded Cryptographic Key","description":"The use of a hard-coded cryptographic key significantly increases the possibility that encrypted data may be recovered.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/SupportResource.scala#L105","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/SupportResource.scala#L108","cwes":["CWE-321"],"path":"SupportResource.scala:108"}'

# CWE-338 — Cryptographically Weak PRNG
submit '{"title":"Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)","description":"The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNGs algorithm is not cryptographically strong.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/OneApplicationResource.scala#L525","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/OneApplicationResource.scala#L530","cwes":["CWE-338"],"path":"OneApplicationResource.scala:530"}'

# CWE-614 — Sensitive Cookie Without 'Secure' Attribute
submit '{"title":"Sensitive Cookie in HTTPS Session Without Secure Attribute","description":"The Secure attribute for sensitive cookies in HTTPS sessions is not set, which could cause the user agent to send those cookies in plaintext over an HTTP session.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/SupportResource.scala#L123","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/SupportResource.scala#L128","cwes":["CWE-614"],"path":"SupportResource.scala:128"}'

# CWE-1004 — Sensitive Cookie Without 'HttpOnly' Flag
submit '{"title":"Sensitive Cookie Without HttpOnly Flag","description":"The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.","source":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/StagesResource.scala#L377","sink":"'"$BASE"'/core/src/main/scala/org/apache/spark/status/api/v1/StagesResource.scala#L382","cwes":["CWE-1004"],"path":"StagesResource.scala:382"}'
