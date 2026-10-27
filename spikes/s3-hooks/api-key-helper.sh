#!/bin/sh
# Spike S3 step 4: apiKeyHelper that prints the canary (fake key) read from $AV_CANARY_FILE.
cat "$AV_CANARY_FILE"
