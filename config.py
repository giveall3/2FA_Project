import os

class Config:
    #Keys location
    SECRET_KEY = os.environ.get("SESSION_SECRET", "dev_session_change_me")
    JWT_SECRET = os.environ.get("JWT_SECRET", os.environ.get("SESSION_SECRET", "dev_session_change_me"))
    JWT_EXP_SECONDS = int(os.environ.get("JWT_EXP_SECONDS", "600")) #Webtoken timeout
    GAME_PLUGIN_API_KEY = os.environ.get("GAME_PLUGIN_API_KEY") or os.environ.get("API_KEY", "CHANGE_ME")
    API_KEY = GAME_PLUGIN_API_KEY  # alias for comfort
    #Database location
    DB_PATH    = os.environ.get("DATABASE_URL", os.path.join("data", "auth.db"))
    #Cookie safety
    SESSION_COOKIE_HTTPONLY = True # Cookies only for server (NOT JS)
    SESSION_COOKIE_SAMESITE = "Lax" # Protecc from typical CSRF (Cross-Site Request Forgery)
    SESSION_COOKIE_SECURE   = False # ProdConfig launches that

class DevConfig(Config): #Auto-reload, better logs and easier for dev
    DEBUG = True

class ProdConfig(Config): #No dev, cookies only in HTTPS
    DEBUG = False
    SESSION_COOKIE_SECURE = True