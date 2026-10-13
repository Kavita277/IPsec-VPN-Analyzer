"""AI explanation layer (Person 3). Explains findings; never decides them."""

from ai.explain import explain, guard
from ai.facts import build_facts
from ai.providers import AnthropicProvider, ProviderError, TemplateProvider, get_provider

__all__ = [
    "AnthropicProvider", "ProviderError", "TemplateProvider",
    "build_facts", "explain", "get_provider", "guard",
]
