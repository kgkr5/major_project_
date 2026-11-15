"""
Ollama LLM service for AgentShield.

Wraps the Ollama REST API for local LLM inference.
Falls back gracefully when Ollama is unavailable.
"""

import json
import logging
from typing import Any, Dict, Optional

import httpx

from backend.core.config import settings

logger = logging.getLogger(__name__)


class OllamaService:
    """
    Client for the Ollama local LLM runtime.
    Returns None on any connection/timeout error so callers can fall back.
    """

    def __init__(self) -> None:
        self._host = settings.ollama_host
        self._model = settings.ollama_model
        self._timeout = settings.ollama_timeout_seconds
        self._available: Optional[bool] = None  # cached health state

    async def generate(self, prompt: str) -> Optional[str]:
        """
        Send a generation request to Ollama. Returns the generated text or None.
        Errors are logged but not raised — the caller must handle None.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._host}/api/generate",
                    json={
                        "model": self._model,
                        "prompt": prompt,
                        "stream": False,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                text = data.get("response", "").strip()
                self._available = True
                return text if text else None
        except httpx.ConnectError:
            logger.warning("Ollama not reachable at %s", self._host)
            self._available = False
        except httpx.TimeoutException:
            logger.warning("Ollama request timed out after %ds", self._timeout)
            self._available = False
        except Exception as exc:
            logger.warning("Ollama error: %s", exc)
            self._available = False
        return None

    async def health_check(self) -> Dict[str, Any]:
        """
        Check if Ollama is running and the configured model is available.
        Returns a status dict.
        """
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{self._host}/api/tags")
                resp.raise_for_status()
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                model_available = any(
                    self._model in m or m.startswith(self._model.split(":")[0])
                    for m in models
                )
                self._available = True
                return {
                    "status": "OK" if model_available else "DEGRADED",
                    "message": (
                        f"Model '{self._model}' ready"
                        if model_available
                        else f"Model '{self._model}' not found. Available: {models}"
                    ),
                    "available_models": models,
                }
        except httpx.ConnectError:
            self._available = False
            return {
                "status": "DOWN",
                "message": f"Ollama not reachable at {self._host}",
            }
        except Exception as exc:
            self._available = False
            return {"status": "DOWN", "message": str(exc)}

    @property
    def is_available(self) -> bool:
        return self._available is True


# Global singleton
ollama_service = OllamaService()
