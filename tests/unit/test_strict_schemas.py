import json

import pytest
from pydantic import ValidationError

from argus_img.core.config import load_config
from argus_img.core.detector_registry import DetectorRegistry
from argus_img.core.exceptions import ConfigurationError
from argus_img.core.models import DetectorReport
from argus_img.detectors.prompt.rules import PromptRuleBundle
from argus_img.policy.decisions import PolicyDocument
from argus_img.reporting.json_schema import scan_report_schema


BASE_POLICY = {
    "profile": "AGENT_WITH_TOOLS",
    "rules": [
        {
            "id": "block-prompt",
            "priority": 100,
            "when": {"category": "prompt_injection", "state": "CONFIRMED"},
            "action": "BLOCK",
        }
    ],
}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.update({"unknown": True}),
        lambda data: data["rules"][0].update({"unknown": True}),
        lambda data: data["rules"][0]["when"].update({"unknown_operator": True}),
        lambda data: data["rules"][0].update({"action": "ALLOW_EVERYTHING"}),
        lambda data: data["rules"][0]["when"].update({"state": "SAFE"}),
        lambda data: data["rules"][0]["when"].update({"category": "unknown_category"}),
        lambda data: data.update({"rules": []}),
        lambda data: data["rules"].append(dict(data["rules"][0])),
        lambda data: data["rules"][0].update({"when": {}}),
        lambda data: data["rules"][0]["when"].update({"greater_than_or_equal": {"attack_likelihood": 2.0}}),
    ],
)
def test_policy_schema_rejects_invalid_documents(mutate):
    data = json.loads(json.dumps(BASE_POLICY))
    mutate(data)
    with pytest.raises(ValidationError):
        PolicyDocument.model_validate(data)


def test_config_schema_rejects_unknown_fields(tmp_path):
    override = tmp_path / "config.yaml"
    override.write_text("unknown_field: true\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(override)


def test_detector_registry_rejects_duplicate_ids():
    with pytest.raises(ValidationError):
        DetectorRegistry.model_validate(
            {
                "detectors": [
                    {"id": "detector:one", "family": "metadata", "category": "privacy"},
                    {"id": "detector:one", "family": "metadata", "category": "privacy"},
                ]
            }
        )


def test_prompt_rule_bundle_rejects_unknown_fields_and_duplicate_ids(tmp_path):
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text(
        "rules:\n"
        "  - id: PI-1\n"
        "    category: instruction_override\n"
        "    patterns: ['ignore previous instructions']\n",
        encoding="utf-8",
    )
    second.write_text(
        "rules:\n"
        "  - id: PI-1\n"
        "    category: instruction_override\n"
        "    patterns: ['override system prompt']\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        PromptRuleBundle.load(first, second)
    first.write_text(
        "rules:\n"
        "  - id: PI-2\n"
        "    category: instruction_override\n"
        "    patterns: ['ignore previous instructions']\n"
        "    unexpected: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        PromptRuleBundle.load(first)


def test_committed_json_schemas_do_not_drift():
    expected = {
        "scan-report.schema.json": scan_report_schema(),
        "detector-report.schema.json": DetectorReport.model_json_schema(),
        "policy.schema.json": PolicyDocument.model_json_schema(),
    }
    for filename, schema in expected.items():
        committed = json.loads((__import__("pathlib").Path("schemas") / filename).read_text(encoding="utf-8"))
        assert committed == json.loads(json.dumps(schema, sort_keys=True))
