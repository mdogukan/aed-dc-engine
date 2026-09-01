import secrets
import string

class HoneytokenGenerator:
    @staticmethod
    def generate_aws_keys():
        """Gerçekçi formatta sahte AWS Access Key ve Secret Key üretir."""
        chars = string.ascii_uppercase + string.digits
        key_id = "AKIA" + "".join(secrets.choice(chars) for _ in range(16))
        secret_chars = string.ascii_letters + string.digits + "+/="
        secret_key = "".join(secrets.choice(secret_chars) for _ in range(40))
        return key_id, secret_key

    @staticmethod
    def get_env_honeytoken():
        """Saldırgana sunulacak sahte .env dosyası içeriği üretir."""
        aws_id, aws_sec = HoneytokenGenerator.generate_aws_keys()
        db_pass = secrets.token_hex(12)
        jwt_secret = secrets.token_urlsafe(32)

        content = (
            "# Environment Configuration (Production)\n"
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            "APP_KEY=base64:X8fJk2L9qPzNmW1vR4tY7uI0oP3sD6gH5jK8lA=\n\n"
            "# Database Connection\n"
            "DB_CONNECTION=pgsql\n"
            "DB_HOST=192.168.159.240\n"
            "DB_PORT=5432\n"
            "DB_DATABASE=corporate_vault_prod\n"
            "DB_USERNAME=vault_admin\n"
            f"DB_PASSWORD={db_pass}\n\n"
            "# Cloud Storage Credentials\n"
            f"AWS_ACCESS_KEY_ID={aws_id}\n"
            f"AWS_SECRET_ACCESS_KEY={aws_sec}\n"
            "AWS_DEFAULT_REGION=eu-central-1\n"
            "AWS_BUCKET=internal-backup-archive-2026\n\n"
            "# JWT Authentication\n"
            f"JWT_SECRET={jwt_secret}\n"
        )
        return content

    @staticmethod
    def get_robots_txt():
        """Saldırganı daha derin sahte rotalara çeken robots.txt içeriği üretir."""
        return (
            "User-agent: *\n"
            "Disallow: /admin_backup_2026/\n"
            "Disallow: /internal_vault/\n"
            "Disallow: /api/v1/internal/export/\n"
        )
