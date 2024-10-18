import os

SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "postgresql://schoolsystemdatabase_user:XMIC0d70sPEmLgPK9ME2U7WmsNeHN8Pp@dpg-cs93bttds78s73c84h3g-a.oregon-postgres.render.com/schoolsystemdatabase")
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = 'your-secret-key'  # Change this to a secure random key
JWT_SECRET_KEY = 'your-jwt-secret-key'  # Change this to a different secure random key

# postgresql://schoolsystemdatabase_user:XMIC0d70sPEmLgPK9ME2U7WmsNeHN8Pp@dpg-cs93bttds78s73c84h3g-a.oregon-postgres.render.com/schoolsystemdatabase