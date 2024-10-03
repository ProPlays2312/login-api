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
    "SECRET_KEY": os.environ.get('SECRET_KEY'),
    "DEBUG": os.environ.get('DEBUG'),
    "SESSION_TYPE": "filesystem",
    "SESSION_PERMANENT": False,
    "SESSION_EXPIRES": int(os.environ.get('SESSION_Expires')),
    "SESSION_KEY_PREFIX": "session",
    "SESSION_COOKIE_NAME": "token",
    "SESSION_COOKIE_DOMAIN": "*",
    "SESSION_COOKIE_SAMESITE": "Lax",
}