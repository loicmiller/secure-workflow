package istio.authz
import input.attributes.request.http as http_request

default allow = false

# Get username from input
user_name = parsed {
  [_, encoded] := split(http_request.headers.authorization, " ")
  [parsed, _] := split(base64url.decode(encoded), ":")
}

# RBAC user-role assignments
user_roles = {
  "owner": ["owner"],
  "vfx-1": ["vfx-1"],
  "vfx-2": ["vfx-2"],
  "vfx-3": ["vfx-3"],
  "color": ["color"],
  "sound": ["sound"],
  "hdr": ["hdr"]
}

# RBAC role-permissions assignments
role_permissions = {
  "owner": [{"method": "POST",  "path": "/api/vfx-1"}],
  "vfx-1": [{"method": "POST",  "path": "/api/vfx-2"},
            {"method": "POST",  "path": "/api/vfx-3"}],
  "vfx-2": [{"method": "POST",  "path": "/api/color"}],
  "vfx-3": [{"method": "POST",  "path": "/api/sound"}],
  "color": [{"method": "POST",  "path": "/api/hdr"}],
  "hdr": [{"method": "POST",  "path": "/api/owner"}],
  "sound": [{"method": "POST",  "path": "/api/owner"}]
}

# Logic that implements RBAC
rbac_logic {
  # lookup the list of roles for the user
  roles := user_roles[user_name]
  # for each role in that list
  r := roles[_]
  # lookup the permissions list for role r
  permissions := role_permissions[r]
  # for each permission
  p := permissions[_]
  # check if the permission granted to r matches the user's request
  p == {"method": http_request.method, "path": http_request.path}
}


# ABAC user attributes (tenure)
user_attributes = {
  "owner": {"tenure": 8},
  "vfx-1": {"tenure": 3},
  "vfx-2": {"tenure": 12},
  "vfx-3": {"tenure": 7},
  "color": {"tenure": 3},
  "sound": {"tenure": 4},
  "hdr": {"tenure": 5},
}


allow {
  user_name == "owner"

  # Match method and path (RBAC)
  rbac_logic
}

allow {
  user_name == "vfx-1"

  # Match method and path (RBAC)
  rbac_logic
}

allow {
  user_name == "vfx-2"

  # Match method and path (RBAC)
  rbac_logic

  # Match user attributes (ABAC)
  user:=user_attributes[user_name]
  user.tenure > 10
}

allow {
  user_name == "vfx-2"

  # Match method and path (RBAC)
  rbac_logic

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) >= 8
  to_number(current_time[0]) <= 17
}

allow {
  user_name == "vfx-3"

  # Match method and path (RBAC)
  rbac_logic

  # Match user attributes (ABAC)
  user:=user_attributes[user_name]
  user.tenure > 10
}

allow {
  user_name == "vfx-3"

  # Match method and path (RBAC)
  rbac_logic

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) >= 8
  to_number(current_time[0]) <= 17
}

allow {
  user_name == "color"

  # Match method and path (RBAC)
  rbac_logic

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) <= 8
  to_number(current_time[0]) >= 17
}

allow {
  user_name == "sound"

  # Match method and path (RBAC)
  rbac_logic

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) <= 8
  to_number(current_time[0]) >= 17
}

allow {
  user_name == "hdr"

  # Match method and path (RBAC)
  rbac_logic

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) >= 8
  to_number(current_time[0]) <= 17
}
