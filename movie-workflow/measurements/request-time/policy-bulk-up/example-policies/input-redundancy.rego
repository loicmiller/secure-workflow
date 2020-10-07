# Attribute-based Access Control (ABAC)
# -------------------------------------
#
# This example implements ABAC for a Pet Store API. The Pet Store API allows
# users to look at pets, adopt them, update their stats, and so on. The policy
# controls which users can perform actions on which resources. The policy implements
# a Attribute-based Access Control model where users, resources, and actions have
# attributes and the policy makes decisions based on those attributes.
#
# This example shows how to:
#
# * Implement ABAC using Rego that leverages external data.
# * Define helper rules that provide useful abstractions (e.g., `user_is_senior`).
#
# For more information see:
#
# * Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#
# Hint: The Coverage feature lets you view the policy statements that were executed
# when the policy was last evaluated. Try enabling Coverage and running evaluation
# with different inputs.

package app.abac

default allow = false

allow {
  user_is_owner
}

allow {
  user_is_employee
  action_is_read
}

allow {
  user_is_employee
  user_is_senior
  action_is_update
}

allow {
  user_is_customer
  action_is_read
  pet_is_adopted
}

# Added input redundancy
allow {
  user_is_employee
  action_is_read
  pet_is_adopted
}

user_is_owner {
  data.user_attributes[input.user].title == "owner"
}

user_is_employee {
  data.user_attributes[input.user].title == "employee"
}

user_is_customer {
  data.user_attributes[input.user].title == "customer"
}

user_is_senior {
  data.user_attributes[input.user].tenure > 8
}

action_is_read {
  input.action == "read"
}

action_is_update {
  input.action == "update"
}

pet_is_adopted {
  data.pet_attributes[input.resource].adopted == true
}

