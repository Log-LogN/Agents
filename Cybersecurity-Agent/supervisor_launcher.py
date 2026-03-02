import uvicorn
import logging
from shared.config import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('supervisor.log', mode='a')
    ]
)

if __name__ == "__main__":
    uvicorn.run(
        "agent.supervisor.api:app",
        host="0.0.0.0",
        port=9000,
        reload=False,
    )