package istio.authz

import input.attributes.request.http as http_request

default allow = false

allow {
  roles_for_user[r]
  required_roles[r]
}

roles_for_user[r] {
  r := user_roles[user_name][_]
}

required_roles[r] {
  perm := role_perms[r][_]
  perm.method = http_request.method
  perm.path = http_request.path
}

user_name = parsed {
  [_, _, _, _, _, _, parsed] := split(input.attributes.source.principal, "/")
}

user_roles = {
  "workflow-owner": ["owner"],
  "workflow-adder": ["adder"],
  "workflow-multiplier": ["multiplier"]
}

role_perms = {
  "owner": [
      {"method": "POST",  "path": "/api/adder"}
  ],
  "adder": [
      {"method": "POST",  "path": "/api/multiplier"},
  ],
  "multiplier": [
      {"method": "POST",  "path": "/api/owner"}
  ],
}
