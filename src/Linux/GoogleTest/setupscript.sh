#!/bin/bash

echo 'ScriptName = ' $0
echo 'FirstArgument = ' $1
echo 'SecondArgument = ' $2
echo 'This message should go to stderr' >&2

exit 0