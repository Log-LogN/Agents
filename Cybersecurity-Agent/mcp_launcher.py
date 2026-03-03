import subprocess
import sys
import signal
import time
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

SERVERS = [
    ("mcp_tools.vulnerability.server:create_app", 8001),
    ("mcp_tools.dependency.server:create_app", 8002),
]


class MCPServerManager:
    def __init__(self, servers):
        self.servers = servers
        self.processes = []
        self.running = True

    def start_all(self):
        logging.info("Starting MCP servers...")

        for app_path, port in self.servers:
            cmd = [
                sys.executable,
                "-m",
                "uvicorn",
                app_path,
                "--host",
                "0.0.0.0",
                "--port",
                str(port),
                "--factory",
                "--log-level",
                "info",
            ]

            process = subprocess.Popen(cmd)
            self.processes.append((process, app_path, port))
            logging.info("Started %s on port %s (PID=%s)", app_path, port, process.pid)

        self._monitor()

    def _monitor(self):
        try:
            while self.running:
                for process, app_path, port in self.processes:
                    if process.poll() is not None:
                        logging.error(
                            "Server crashed: %s (port %s, code %s)",
                            app_path,
                            port,
                            process.returncode,
                        )
                        self.shutdown()
                        return
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Keyboard interrupt received.")
            self.shutdown()

    def shutdown(self):
        logging.info("Shutting down all MCP servers...")
        self.running = False

        for process, app_path, port in self.processes:
            logging.info("Stopping %s (PID=%s)", app_path, process.pid)
            process.terminate()

        for process, _, _ in self.processes:
            process.wait()

        logging.info("All MCP servers stopped.")


def handle_signal(signum, frame):
    logging.info("Signal %s received. Exiting...", signum)
    manager.shutdown()
    sys.exit(0)


if __name__ == "__main__":
    manager = MCPServerManager(SERVERS)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    manager.start_all()