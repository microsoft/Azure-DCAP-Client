#!/bin/bash
# To run an exe test in this case we are choosing to use the GoogleTest parser in our AzureGalleryGoogleTestGroup.xml. This GoogleTest json produced below will give an example output that can be parsed.
./dcap_provider_utests --gtest_output=xml:gtestresults.xml

export LoggingDirectory=[WorkingDirectory]\output

# Use the loggingdirectory environment variable to create the example output trx file in that location
echo "Logging directory: " $LoggingDirectory
echo $exampleGoogleTestOutput > $LoggingDirectory/testResult.json