##############################################################
#
# iam_stack.py
#
# Resources:
#   Lambda Execution Role
#
# Exports:
#  lambda_execution_role_arn
#
##############################################################

from aws_cdk import (
  aws_iam as iam,
  core
)

class IAMStack(core.Stack):

  def __init__(self, scope: core.Construct, construct_id: str, env, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)

    # get region for role name
    region=env['region']

    # create lambda execution role, use same role for both lambdas
    self._config_badpol_lambda_role=iam.Role(self,"BadPol Lambda Role",
      role_name="Config_BadPol_Lambda_Execution_Role-"+region,
      assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
      inline_policies=[iam.PolicyDocument(
        statements=[iam.PolicyStatement(
          actions=[
            # not needed?
            "iam:List*"
          ],
          effect=iam.Effect.ALLOW,
          resources=["*"]
        )]
      )],
      managed_policies=[
        iam.ManagedPolicy.from_aws_managed_policy_name('job-function/ViewOnlyAccess'),
        iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole'),
        iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSConfigRulesExecutionRole')
      ]
    ).without_policy_updates()

  # Exports
  @property
  def config_badpol_lambda_role(self) -> iam.IRole:
    return self._config_badpol_lambda_role