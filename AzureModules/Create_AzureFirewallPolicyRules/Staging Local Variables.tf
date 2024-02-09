############################################################ Define Staging Local Variables #######################################################

# Extract Firewall Rulles from CSV file
locals {
  firewall_rules = csvdecode(file(var.firewall_rules_csvfile_Path))
}


# Extract CollectionGroups, RuleCollections, Nat_Rules, Network_Rules and Application_Rules from local.firewall_rules
locals {
  CollectionGroups = distinct(
                      [for Rule in local.firewall_rules :
                              {
                                "CollectionGroupName"  = trim(Rule.CollectionGroupName, " ") # Remove all Spaces from start and End of String
                                "Priority"             = trim(Rule.CG_Priority, " ")
                              }
                      ]
                    )

  RuleCollections = distinct(
                      [for Rule in local.firewall_rules :
                              {
                                "CollectionGroupName"  = trim(Rule.CollectionGroupName, " ")
                                "RuleCollectionName"   = trim(Rule.RuleCollectionName, " ")
                                "Type"                 = trim(Rule.RC_Type, " ")
                                "Priority"             = trim(Rule.RC_Priority, " ")
                                "Action"               = trim(Rule.RC_Action, " ")
                              }
                      ]
                    )

  Nat_Rules = [  for Rule in local.firewall_rules :
                      {
                        "CollectionGroupName"      = trim(Rule.CollectionGroupName, " ")
                        "RuleCollectionName"       = trim(Rule.RuleCollectionName, " ")
                        "RuleName"                 = trim(Rule.RuleName, " ")
                        "SourceType"               = trim(Rule.SourceType, " ")
                        "Source"                   = replace(Rule.Source, " ", "")   # Remove all Spaces in the String
                        "Protocol"                 = replace(Rule.Protocol, " ", "")
                        "Destination_Firewall_IP"  = replace(Rule.Destination, " ", "")
                        "DestinationPort"          = replace(Rule.DestinationPort, " ", "")
                        "TranslatedAddress"        = trim(Rule.TranslatedAddress, " ")
                        "TranslatedPort"           = trim(Rule.TranslatedPort, " ")
                      }
                if trim(Rule.RC_Type, " ") == "NAT"
             ]

  Network_Rules = [  for Rule in local.firewall_rules :
                          {
                            "CollectionGroupName"      = trim(Rule.CollectionGroupName, " ")
                            "RuleCollectionName"       = trim(Rule.RuleCollectionName, " ")
                            "RuleName"                 = trim(Rule.RuleName, " ")
                            "SourceType"               = trim(Rule.SourceType, " ")
                            "Source"                   = replace(Rule.Source, " ", "")
                            "Protocol"                 = replace(Rule.Protocol, " ", "")
                            "DestinationType"          = trim(Rule.DestinationType, " ")
                            "Destination"              = replace(Rule.Destination, " ", "")
                            "DestinationPort"          = replace(Rule.DestinationPort, " ", "")
                          }
                    if trim(Rule.RC_Type, " ") == "Network"
                 ]

  Application_Rules = [  for Rule in local.firewall_rules :
                              {
                                "CollectionGroupName"      = trim(Rule.CollectionGroupName, " ")
                                "RuleCollectionName"       = trim(Rule.RuleCollectionName, " ")
                                "RuleName"                 = trim(Rule.RuleName, " ")
                                "SourceType"               = trim(Rule.SourceType, " ")
                                "Source"                   = replace(Rule.Source, " ", "")
                                "Protocol"                 = replace(Rule.Protocol, " ", "")
                                "DestinationType"          = trim(Rule.DestinationType, " ")
                                "Destination"              = replace(Rule.Destination, " ", "")
                                "DestinationPort"          = replace(Rule.DestinationPort, " ", "")
                                "TLSAction"                = trim(Rule.TLSAction, " ")
                              }
                         if trim(Rule.RC_Type, " ") == "Application"
                      ]
}


# Extract all Existing IPGroups from local.firewall_rules
# IP groups are expected to be existing in Azure envirnment otherwise it will throw an Error
locals {
  Existing_IPGroups=distinct(flatten( [
                                        [ for Rule in local.firewall_rules :
                                              split("," , replace(Rule.Source, " ", "") )
                                          if trim(Rule.SourceType, " ") == "IPGroup"
                                        ],
                                        [ for Rule in local.firewall_rules :
                                              split("," , replace(Rule.Destination, " ", "") )
                                          if trim(Rule.DestinationType, " ") == "IPGroup"
                                        ]
                                      ]
                                    ))
}