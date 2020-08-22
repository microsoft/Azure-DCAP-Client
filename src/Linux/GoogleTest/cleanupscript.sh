#!/bin/bash

echo 'ScriptName = ' $0
echo 'FirstArgument = ' $1
echo 'SecondArgument = ' $2
echo 'This message should go to stderr' >&2

# Copy files to $LoggingDirectory so they can be uploaded as attachments
echo 'Logging directory: ' $LoggingDirectory
echo 'This is a sample attachment file' > $LoggingDirectory/attachment.txt

exit 0