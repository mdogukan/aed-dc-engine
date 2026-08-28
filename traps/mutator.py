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

