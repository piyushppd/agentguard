"""Optional: plug a real model in as the second-opinion critic.

Standard library only. Reads ANTHROPIC_API_KEY from the environment.
To use a different family (the point of an independent critic), write an
equivalent function for OpenAI, Bedrock, or a local Ollama model:

    def ollama_critic(prompt):  # e.g. llama3 running locally
        body = json.dumps({"model": "llama3", "prompt": prompt, "stream": False}).encode()
        req = urllib.request.Request("http://localhost:11434/api/generate", body,
                                     {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req))["response"]
"""
from __future__ import annotations

import json
import os
import urllib.request


def claude_critic(prompt: str, model: str = "claude-sonnet-5-5") -> str:
    key = os.environ["ANTHROPIC_API_KEY"]
    body = json.dumps({
        "model": model,
        "max_tokens": 300,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", body,
        {"x-api-key": key, "anthropic-version": "2023-06-01",
         "content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)["content"][0]["text"]
