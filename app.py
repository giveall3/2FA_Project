from config import DevConfig #Reads settings from config.py in dev mode (change DevConfig for ProdConfig)
from app import create_app #making flask app

app = create_app(DevConfig) #makes app from settings

if __name__ == "__main__": #launches local dev server
    app.run(host="0.0.0.0", port=5000)
