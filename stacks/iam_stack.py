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

    # get acct id for policies
    # acct_id=env['account']

    # create lambda execution role, use same role for both lambdas
    self._config_badpol_lambda_role=iam.Role(self,"BadPol Lambda Role",
      role_name="Config_BadPol_Lambda_Execution_Role",
      assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
      managed_policies=[
        iam.ManagedPolicy.from_aws_managed_policy_name('IAMReadOnlyAccess'),
        iam.ManagedPolicy.from_aws_managed_policy_name('service-role/AWSLambdaBasicExecutionRole')  
      ]
    )

  # Exports
  @property
  def config_badpol_lambda_role(self) -> iam.IRole:
    return self._config_badpol_lambda_role