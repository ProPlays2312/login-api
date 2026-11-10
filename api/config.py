import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    DEBUG = False
    TESTING = False


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig,
    "SECRET_KEY": os.environ.get('SECRET_KEY', 'default-secret-key'),
    "DEBUG": os.environ.get('DEBUG', 'False'),
    "SESSION_TYPE": "filesystem",
    "SESSION_PERMANENT": False,
    "SESSION_EXPIRES": int(os.environ.get('SESSION_Expires', '3600') or 3600),
    "SESSION_KEY_PREFIX": "session",
    "SESSION_COOKIE_NAME": "token",
    "SESSION_COOKIE_DOMAIN": "*",
    "SESSION_COOKIE_SAMESITE": "Lax",
}
