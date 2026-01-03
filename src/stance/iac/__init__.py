"""
Infrastructure as Code (IaC) scanning module for Mantissa Stance.

Provides static analysis capabilities for:
- Terraform (HCL) files
- CloudFormation (JSON/YAML) templates
- Azure ARM templates
- Kubernetes manifests

All parsing is deterministic and does not require external tools.
"""

from __future__ import annotations

from stance.iac.base import (
    IaCFile,
    IaCFormat,
    IaCLocation,
    IaCResource,
    IaCParser,
    IaCFinding,
    IaCParseResult,
    IaCScanner,
)
from stance.iac.terraform import (
    TerraformParser,
    TerraformResource,
    parse_terraform_file,
    parse_terraform_directory,
)
from stance.iac.cloudformation import (
    CloudFormationParser,
    CloudFormationResource,
    SimpleYAMLParser,
    parse_cloudformation_file,
    parse_cloudformation_content,
)
from stance.iac.arm import (
    ARMTemplateParser,
    ARMTemplateResource,
    parse_arm_template_file,
    parse_arm_template_content,
)
from stance.iac.policies import (
    IaCPolicy,
    IaCPolicyCheck,
    IaCPolicyCollection,
    IaCPolicyCompliance,
    IaCPolicyLoader,
    IaCPolicyEvaluator,
    get_default_iac_policies,
)

__all__ = [
    # Base classes
    "IaCFile",
    "IaCFormat",
    "IaCLocation",
    "IaCResource",
    "IaCParser",
    "IaCFinding",
    "IaCParseResult",
    "IaCScanner",
    # Terraform
    "TerraformParser",
    "TerraformResource",
    "parse_terraform_file",
    "parse_terraform_directory",
    # CloudFormation
    "CloudFormationParser",
    "CloudFormationResource",
    "SimpleYAMLParser",
    "parse_cloudformation_file",
    "parse_cloudformation_content",
    # ARM
    "ARMTemplateParser",
    "ARMTemplateResource",
    "parse_arm_template_file",
    "parse_arm_template_content",
    # Policies
    "IaCPolicy",
    "IaCPolicyCheck",
    "IaCPolicyCollection",
    "IaCPolicyCompliance",
    "IaCPolicyLoader",
    "IaCPolicyEvaluator",
    "get_default_iac_policies",
]
