import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = 7 * 24 * 60 * 60  # 7 days

    # File Upload Configuration
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))  # Get base directory
    FILE_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads/files')# Save uploads in 'uploads' folder
    IMAGE_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads/cover_images')
    ALLOWED_EXTENSIONS = {'pdf', 'epub', 'jpg', 'jpeg', 'png'}  # Allowed file types

    # Encryption Key
    ENCRYPTION_KEY = os.getenv('FILE_ENCRYPTION_KEY').encode()

    # Ensure the upload folder exists
    if not os.path.exists(FILE_UPLOAD_FOLDER):
        os.makedirs(FILE_UPLOAD_FOLDER)

    # Ensure the upload folder exists for cover image
    if not os.path.exists(IMAGE_UPLOAD_FOLDER):
        os.makedirs(IMAGE_UPLOAD_FOLDER)