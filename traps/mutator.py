import random

class ServiceMutator:
    @staticmethod
    def get_http_banner():
        servers = [
            "Apache/2.4.52 (Ubuntu)",
            "nginx/1.18.0 (Ubuntu)",
            "Microsoft-IIS/10.0",
            "LiteSpeed/5.4.12"
        ]
        chosen = random.choice(servers)
        body = "<html><body><h1>502 Bad Gateway</h1></body></html>"
        return (
            f"HTTP/1.1 502 Bad Gateway\r\n"
            f"Server: {chosen}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n{body}"
        ).encode("utf-8")

    @staticmethod
    def get_ssh_banner():
        ssh_versions = [
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
            "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
            "SSH-2.0-OpenSSH_7.4\r\n"
        ]
        return random.choice(ssh_versions).encode("utf-8")
