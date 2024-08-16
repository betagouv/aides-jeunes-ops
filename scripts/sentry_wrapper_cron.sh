#!/bin/bash

# This script is executing the command passed as 2nd argument 
# and send an event to Sentry if the command fails.
# The .env file path is passed as the first argument.


ENV_FILE_PATH=$1
shift # Remove the first argument
if [ -z "$ENV_FILE_PATH" ]; then
    echo "Error: .env file path is missing"
    exit 1
fi
source $ENV_FILE_PATH

if [ -z "$SENTRY_CRON_DSN" ]; then
    echo "Error: SENTRY_CRON_DSN is not set in .env file"
    exit 1
fi

echo "SENTRY_CRON_DSN is set to: $SENTRY_CRON_DSN"

# The wrapped command is executed and the result status is stored
COMMAND="$@"
OUTPUT=$(eval "$COMMAND" 2>&1)
STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "Cron job failed: $COMMAND"
    echo "Error output: $OUTPUT"
    SENTRY_DSN="$SENTRY_CRON_DSN" sentry-cli send-event -m "Cron job failed: $COMMAND | Error: $OUTPUT"
fi

exit $STATUS