from __future__ import annotations

from pydantic import BaseModel, Field


class RepoDependencyScanRequest(BaseModel):
    repo_url: str = Field(..., description="Public GitHub repo URL, e.g. https://github.com/org/repo")


class TextDependencyScanRequest(BaseModel):
    content: str = Field(..., description="Dependency file contents (requirements.txt or package.json)")
    file_type: str = Field(..., description="requirements.txt | package.json")

