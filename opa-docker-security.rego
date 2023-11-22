package main

# Do Not store secrets in ENV variables
secrets_env = [
    "passwd",
    "password",
    "pass",
    "secret",
    "key",
    "access",
    "api_key",
    "apikey",
    "token",
    "tkn"
]

deny[msg] {
    input[i].Cmd == "env"
    val := input[i].Value
    contains(lower(val[_]), secrets_env[_])
    msg = sprintf("Potential secret in ENV key found: %v", [val])
}

# Do not use 'latest' tag for base images
deny[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    contains(lower(val[1]), "latest")
    msg = sprintf("Do not use 'latest' tag for base images")
}

# Avoid curl bashing
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    matches := regex.find_n("(curl|wget)[^|^>]*[|>]", lower(val), -1)
    count(matches) > 0
    msg = sprintf("Avoid curl bashing")
}

# Do not upgrade your system packages
warn[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    matches := regex.match(".*?(apk|yum|dnf|apt|
