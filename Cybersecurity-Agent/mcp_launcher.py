import subprocess
import sys


SERVERS = [
    ("mcp_tools.recon.server:create_app", 8001),
    ("mcp_tools.reporting.server:create_app", 8002),
    ("mcp_tools.vulnerability.server:create_app", 8003),
    ("mcp_tools.threat_intel.server:create_app", 8004),
    ("mcp_tools.risk_engine.server:create_app", 8005),
    ("mcp_tools.dependency.server:create_app", 8006),
]


class MCPServerManager:
    def __init__(self, servers):
        self.servers = servers
        self.processes = []

    def start_all(self):
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
            ]

            p = subprocess.Popen(cmd)
            self.processes.append(p)
            print(f"Started {app_path} on port {port}")

        # Wait for all
        for p in self.processes:
            p.wait()


if __name__ == "__main__":
    manager = MCPServerManager(SERVERS)
    manager.start_all()
