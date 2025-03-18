import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = 7 * 24 * 60 * 60  # 7 days

    # Determine storage path
    if os.getenv('VERCEL'):
        FILE_UPLOAD_FOLDER = '/tmp/uploads/files'
        IMAGE_UPLOAD_FOLDER = '/tmp/uploads/cover_images'
    else:
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        FILE_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads/files')
        IMAGE_UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads/cover_images')

    ALLOWED_EXTENSIONS = {'pdf', 'epub', 'jpg', 'jpeg', 'png'}  # Allowed file types

    # Encryption Key
    ENCRYPTION_KEY = os.getenv('FILE_ENCRYPTION_KEY').encode()

    # Ensure the upload folders exist
    os.makedirs(FILE_UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(IMAGE_UPLOAD_FOLDER, exist_ok=True)
