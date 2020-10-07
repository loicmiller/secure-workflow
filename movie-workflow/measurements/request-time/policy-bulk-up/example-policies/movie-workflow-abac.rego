package istio.authz
import input.attributes.request.http as http_request

default allow = false

# Get username from input
user_name = parsed {
  [_, encoded] := split(http_request.headers.authorization, " ")
  [parsed, _] := split(base64url.decode(encoded), ":")
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

  # Match method and path
  http_request.path == "/api/vfx-1"
  http_request.method == "POST"
}

allow {
  user_name == "vfx-1"

  # Match method and path
  http_request.path == "/api/vfx-2"
  http_request.method == "POST"
}

allow {
  user_name == "vfx-1"

  # Match method and path
  http_request.path == "/api/vfx-3"
  http_request.method == "POST"
}

allow {
  user_name == "vfx-2"

  # Match method and path
  http_request.path == "/api/color"
  http_request.method == "POST"

  # Match user attributes (ABAC)
  user:=user_attributes[user_name]
  user.tenure > 10
}

allow {
  user_name == "vfx-2"

  # Match method and path
  http_request.path == "/api/color"
  http_request.method == "POST"

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) >= 8
  to_number(current_time[0]) <= 17
}

allow {
  user_name == "vfx-3"

  # Match method and path
  http_request.path == "/api/sound"
  http_request.method == "POST"

  # Match user attributes (ABAC)
  user:=user_attributes[user_name]
  user.tenure > 10
}

allow {
  user_name == "vfx-3"

  # Match method and path
  http_request.path == "/api/sound"
  http_request.method == "POST"

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) >= 8
  to_number(current_time[0]) <= 17
}


allow {
  user_name == "color"

  # Match method and path
  http_request.path == "/api/hdr"
  http_request.method == "POST"

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) <= 8
}

allow {
  user_name == "color"

  # Match method and path
  http_request.path == "/api/hdr"
  http_request.method == "POST"

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) >= 17
}


allow {
  user_name == "sound"

  # Match method and path
  http_request.path == "/api/owner"
  http_request.method == "POST"

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) <= 8
}

allow {
  user_name == "sound"

  # Match method and path
  http_request.path == "/api/owner"
  http_request.method == "POST"

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) >= 17
}


allow {
  user_name == "hdr"

  # Match method and path
  http_request.path == "/api/owner"
  http_request.method == "POST"

  current_time := time.clock([time.now_ns(), "Europe/Paris"])
  to_number(current_time[0]) >= 8
  to_number(current_time[0]) <= 17
}
