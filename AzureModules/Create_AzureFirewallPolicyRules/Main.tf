/*
.DESCRIPTION
  Create Firewall Rules in the existing Azure firewall Policy.

.Authors
  Karim Atef
  Mohamed Zain

.Version
  1.0

.Change Reference
  Updated by Karim Atef on 3 February 2024
*/


###################################### Fetch existing Azure Resources ##########################################################

# Fetch the existing firewall Policy
data "azurerm_firewall_policy" "firewall_policy" {
  name                = var.Existing-FW-policy-Name
  resource_group_name = var.Existing-FW-policy-RG
}

# Fetch the existing IPGroups
data "azurerm_resources" "Existing_IPGroups" {
  for_each = toset(local.Existing_IPGroups)

  type = "Microsoft.Network/ipGroups"
  name = each.key

  lifecycle {
    postcondition {
      condition     = length(self.resources) != 0
      error_message = "'${self.name}' IPGroup is not existing. please create it first."
    }
  }

}

# Extract the Id & RG of each fetched IPgroup in data.azurerm_resources.Existing_IPGroups
locals {
  IPGroups = { for IPGroup, IPGroup_info in data.azurerm_resources.Existing_IPGroups : 
                        IPGroup => {
                                        id = IPGroup_info.resources[0].id
                                        rg_name = split("/" , IPGroup_info.resources[0].id)[4] 
                                    }
             }
}


###################################### Create Rules in the Existing firewall_policy ################################################

resource "azurerm_firewall_policy_rule_collection_group" "Collection_Groups" {
  for_each = {
    for Group in local.CollectionGroups : Group.CollectionGroupName => Group
  }
    
  name               = each.key
  priority           = tonumber(each.value.Priority)
  firewall_policy_id = data.azurerm_firewall_policy.firewall_policy.id

  ################# Nat Rules ##################
  dynamic "nat_rule_collection" {
    for_each = [for Collection in local.RuleCollections : Collection if Collection.Type == "NAT" && Collection.CollectionGroupName == each.key]

    content {
      name     = nat_rule_collection.value["RuleCollectionName"]
      priority = tonumber(nat_rule_collection.value["Priority"])
      action   = nat_rule_collection.value["Action"]

      dynamic "rule" {
        for_each = [ for Rule in local.Nat_Rules : Rule 
                     if Rule.RuleCollectionName == nat_rule_collection.value["RuleCollectionName"] && Rule.CollectionGroupName == each.key
                   ]

        content {
          name                = rule.value["RuleName"]
          protocols           = split(",", rule.value["Protocol"])
          source_addresses    = rule.value["SourceType"] == "IPAddress" ? split(",", rule.value["Source"]) : []
          source_ip_groups    = rule.value["SourceType"] == "IPGroup"   ? [for IPGroup in split(",", rule.value["Source"]) : local.IPGroups[IPGroup].id] : []
          destination_address = rule.value["Destination_Firewall_IP"]
          destination_ports   = split(",", rule.value["DestinationPort"])
          translated_address  = rule.value["TranslatedAddress"]
          translated_port     = rule.value["TranslatedPort"]
        }
      }
    }
  }

  ################# Network Rules ##################
  dynamic "network_rule_collection" {
    for_each = [for Collection in local.RuleCollections : Collection if Collection.Type == "Network" && Collection.CollectionGroupName == each.key]

    content {
      name     = network_rule_collection.value["RuleCollectionName"]
      priority = tonumber(network_rule_collection.value["Priority"])
      action   = network_rule_collection.value["Action"]

      dynamic "rule" {
        for_each = [ for Rule in local.Network_Rules : Rule 
                     if Rule.RuleCollectionName == network_rule_collection.value["RuleCollectionName"] && Rule.CollectionGroupName == each.key
                   ]

        content {
          name                  = rule.value["RuleName"]
          protocols             = split(",", rule.value["Protocol"])
          source_addresses      = rule.value["SourceType"] == "IPAddress"      ? split(",", rule.value["Source"]) : []
          source_ip_groups      = rule.value["SourceType"] == "IPGroup"        ? [for IPGroup in split(",", rule.value["Source"]) : local.IPGroups[IPGroup].id] : []
          destination_addresses = rule.value["DestinationType"] == "IPAddress" ? split(",", rule.value["Destination"]) : []
          destination_fqdns     = rule.value["DestinationType"] == "FQDN"      ? split(",", rule.value["Destination"]) : []
          destination_ip_groups = rule.value["DestinationType"] == "IPGroup"   ? [for IPGroup in split(",", rule.value["Destination"]) : local.IPGroups[IPGroup].id] : []
          destination_ports     = split(",", rule.value["DestinationPort"])
          
        }
      }
    }
  }

  ################# Application Rules ##################
  dynamic "application_rule_collection" {
    for_each = [for Collection in local.RuleCollections : Collection if Collection.Type == "Application" && Collection.CollectionGroupName == each.key]

    content {
      name     = application_rule_collection.value["RuleCollectionName"]
      priority = tonumber(application_rule_collection.value["Priority"])
      action   = application_rule_collection.value["Action"]

      dynamic "rule" {
        for_each = [ for Rule in local.Application_Rules : Rule 
                     if Rule.RuleCollectionName == application_rule_collection.value["RuleCollectionName"] && Rule.CollectionGroupName == each.key
                   ]

        content {
          name              = rule.value["RuleName"]
          source_addresses  = rule.value["SourceType"] == "IPAddress"   ? split(",", rule.value["Source"]) : []
          source_ip_groups  = rule.value["SourceType"] == "IPGroup"     ? [for IPGroup in split(",", rule.value["Source"]) : local.IPGroups[IPGroup].id] : []
          destination_urls  = rule.value["DestinationType"] == "URL"    ? split(",", rule.value["Destination"]) : []
          destination_fqdns = rule.value["DestinationType"] == "FQDN"   ? split(",", rule.value["Destination"]) : []
          terminate_tls     = rule.value["TLSAction"] == "yes" ? true : false

          dynamic "protocols" {
            for_each = split(",", rule.value["Protocol"])

            content {
              type = lower(split(":", protocols.value)[0]) == "http" ? "Http" : ( lower(split(":", protocols.value)[0]) == "https" ? "Https" : null )
              
              port = strcontains(protocols.value, ":") ? split(":", protocols.value)[1] : ( lower(protocols.value) == "http" ? "80" : ( lower(protocols.value) == "https" ? "443" : null ) )
            }
          }
        }
      }
    }
  }

}
