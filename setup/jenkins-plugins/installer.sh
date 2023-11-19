#!/bin/bash

set -eo pipefail

JENKINS_URL='http://localhost:8080'
JENKINS_USER='admin'
JENKINS_PASSWORD='admin123'

# Function to get Jenkins crumb
get_crumb() {
    curl -s --cookie-jar /tmp/cookies -u "${JENKINS_USER}:${JENKINS_PASSWORD}" "${JENKINS_URL}/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)"
}

# Function to install a Jenkins plugin
install_plugin() {
    local plugin_name="$1"
    local crumb=$(get_crumb)

    echo "Installing plugin: ${plugin_name}"
    curl -s -X POST --data "<jenkins><install plugin='${plugin_name}' /></jenkins>" -H 'Content-Type: text/xml' -H "${crumb}" "${JENKINS_URL}/pluginManager/installNecessaryPlugins" --cookie /tmp/cookies --user "${JENKINS_USER}:${JENKINS_PASSWORD}"
}

# Read plugins from the plugins.txt file and install each one
while IFS= read -r plugin; do
    install_plugin "$plugin"
done < plugins.txt

echo "Plugin installation complete."
