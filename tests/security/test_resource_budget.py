import pytest

from argus_img.core.budget import ResourceBudget
from argus_img.core.exceptions import ResourceLimitExceeded
from argus_img.core.limits import Limits


def test_resource_budget_rejects_excess_transformed_pixels():
    budget = ResourceBudget(Limits(max_transformed_pixels=10))
    budget.consume_transformed_pixels(9)
    with pytest.raises(ResourceLimitExceeded):
        budget.consume_transformed_pixels(2)


def test_resource_budget_rejects_excess_text_bytes():
    budget = ResourceBudget(Limits(max_text_bytes=5))
    budget.consume_text("12345")
    with pytest.raises(ResourceLimitExceeded):
        budget.consume_text("6")
