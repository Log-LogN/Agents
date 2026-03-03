from pydantic import BaseModel, Field


class RepoDependencyScanRequest(BaseModel):
    repo_url: str = Field(
        ...,
        description="Public GitHub repository URL (https://github.com/org/repo)",
    )


class TextDependencyScanRequest(BaseModel):
    content: str = Field(
        ...,
        description="Raw dependency file contents",
    )
    file_type: str = Field(
        ...,
        description="requirements.txt | package.json | pom.xml",
    )