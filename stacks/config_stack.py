##############################################################
#
# config_stack.py
#
# Resources:
#
#
##############################################################

from aws_cdk import (
  aws_config as config,
  aws_lambda as lambda_,
  core
)

class ConfigStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, config_badpol_lambda_function: lambda_.IFunction, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    config.CustomRule(self,"Bad Pol Config Rule",
      config_rule_name="bad-policy-rule",
      lambda_function=config_badpol_lambda_function,
      configuration_changes=True,
      periodic=True,
      maximum_execution_frequency=config.MaximumExecutionFrequency.ONE_HOUR,
      input_parameters={
        'WhiteUsers': '["kevin","user2"]',
        'WhiteGroups': '["group1","group2"]',
        'WhiteRoles': '["role1","role2"]',
        'WhitePolicies': '["NotFullAccess","NotAdminAccess"]',
        'BadPolicies': '["AdministratorAccess","PowerUserAccess","AmazonEC2RoleforSSM","ReadOnlyAccess"]',
        'NoFullAccess': 'True'
      },
      rule_scope=config.RuleScope.from_resources([
        config.ResourceType.IAM_USER,
        config.ResourceType.IAM_GROUP,
        config.ResourceType.IAM_ROLE
      ])
    )