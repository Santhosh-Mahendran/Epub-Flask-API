from flask import Blueprint, request, jsonify, current_app, send_file, Response, abort
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, decode_token
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from .models import Publisher, Category, Book, File, Reader, Highlight, Note, BooksPurchased, Cart, Wishlist
from .extensions import db, limiter
from datetime import datetime
import os
from cryptography.fernet import Fernet

import time


ph = PasswordHasher()
auth = Blueprint('auth', __name__)
book_bp = Blueprint('book', __name__)
files_bp = Blueprint('files', __name__)
upload_bp = Blueprint('upload', __name__)
category_bp = Blueprint('category', __name__)



@auth.route('/pub/register', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit
def pub_register():
    data = request.json
    required_fields = ["name", "email", "password", "phone", 'geo_location', 'address']

    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    if Publisher.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already registered"}), 400

    hashed_password = ph.hash(data['password'])

    new_publisher = Publisher(
        name=data['name'],
        email=data['email'],
        password=hashed_password,
        phone=data.get('phone'),
        geo_location=data.get('geo_location'),
        address=data.get('address')
    )
    db.session.add(new_publisher)
    db.session.commit()

    return jsonify({"message": "Registration successful"}), 201


@auth.route('/pub/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    publisher = Publisher.query.filter_by(email=data['email']).first()

    if not publisher:
        return jsonify({"error": "Invalid email or password"}), 401

    try:
        if ph.verify(publisher.password, data['password']):
            access_token = create_access_token(identity=str(publisher.publisher_id))
            return jsonify({"access_token": access_token, "message": "Login successful"}), 200
    except VerifyMismatchError:
        return jsonify({"error": "Invalid email or password"}), 401


@book_bp.route('/pub/add_category', methods=['POST'])
@jwt_required()
def add_category():
    data = request.json
    required_fields = ['category_name', 'description']

    # Check if all required fields are present
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    # Get publisher_id from JWT token
    publisher_id = get_jwt_identity()

    # Check if the publisher exists
    publisher = Publisher.query.get(publisher_id)
    if not publisher:
        return jsonify({"error": "Publisher not found"}), 404

    # Create new category
    new_category = Category(
        publisher_id=publisher_id,
        category_name=data['category_name'],
        description=data.get('description'),
        created_at=datetime.utcnow(),
        updated_time=datetime.utcnow()
    )

    # Add category to database
    db.session.add(new_category)
    db.session.commit()

    return jsonify({"message": "Category added successfully", "category": data['category_name']}), 201

@book_bp.route('/pub/get_categories', methods=['GET'])
@jwt_required()
def get_categories():
    publisher_id = get_jwt_identity()
    categories = Category.query.filter_by(publisher_id=publisher_id).all()

    return jsonify({
        "categories": [
            {
                "category_id": category.category_id,
                "category_name": category.category_name,
                "description": category.description,
                "created_at": category.created_at,
                "updated_time": category.updated_time
            }
            for category in categories
        ]
    }), 200


@book_bp.route('/pub/delete_category/<int:category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    try:
        # Get publisher_id from JWT
        publisher_id = get_jwt_identity()

        # Check if category exists and belongs to the publisher
        category = Category.query.filter_by(category_id=category_id, publisher_id=publisher_id).first()

        if not category:
            return jsonify({"error": "Category not found or access denied"}), 404

        # Check if any books are associated with the category
        associated_books = Book.query.filter_by(category_id=category_id).first()
        if associated_books:
            return jsonify({"error": "Cannot delete category with associated books"}), 400

        # Delete category
        db.session.delete(category)
        db.session.commit()

        return jsonify({"message": "Category deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']


# Encrypt the file content using Fernet AES encryption
def encrypt_file(file):
    key = current_app.config['ENCRYPTION_KEY']  # Use a key from a secure location
    cipher = Fernet(key)

    # Read the file content
    file_content = file.read()

    # Encrypt the content
    encrypted_content = cipher.encrypt(file_content)

    return encrypted_content


@files_bp.route('/pub/upload_book', methods=['POST'])
@jwt_required()
def upload_book():
    try:
        publisher_id = get_jwt_identity()
        title = request.form.get('title')
        author = request.form.get('author')
        isbn = request.form.get('isbn')
        category_id = request.form.get('category_id')
        language = request.form.get('language', '')
        genre = request.form.get('genre', '')
        e_book_type = request.form.get('e_book_type', 'EPUB')
        price = request.form.get('price', 0)
        rental_price = request.form.get('rental_price', 0)
        description = request.form.get('description')

        if not all([title, author, isbn, category_id]):
            return jsonify({"error": "Missing required fields"}), 400

        category = Category.query.filter_by(category_id=category_id, publisher_id=publisher_id).first()
        if not category:
            return jsonify({"error": "Invalid category ID"}), 400

        last_book = Book.query.order_by(Book.book_id.desc()).first()
        new_book_id = last_book.book_id + 1 if last_book else 1

        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "No file selected"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type"}), 400

        # Rename file using the new book ID
        file_ext = os.path.splitext(file.filename)[1]
        epub_filename = f"{new_book_id}{file_ext}"
        encrypted_file_content = encrypt_file(file)
        full_file_path = os.path.join(current_app.config['FILE_UPLOAD_FOLDER'], epub_filename + ".enc")
        with open(full_file_path, 'wb') as f:
            f.write(encrypted_file_content)

        cover_image_filename = None
        if 'cover_image' in request.files:
            cover_image = request.files['cover_image']
            if cover_image.filename != '' and allowed_file(cover_image.filename):
                cover_ext = os.path.splitext(cover_image.filename)[1]
                cover_image_filename = f"{new_book_id}{cover_ext}"
                full_cover_image_path = os.path.join(current_app.config['IMAGE_UPLOAD_FOLDER'], cover_image_filename)
                cover_image.save(full_cover_image_path)
            elif cover_image.filename != '':
                return jsonify({"error": "Invalid cover image type"}), 400

        # Check if book title already exists
        existing_book = Book.query.filter_by(title=title).first()
        book_status = 'pending' if existing_book else 'live'

        new_book = Book(
            publisher_id=publisher_id,
            category_id=category_id,
            title=title,
            author=author,
            isbn=isbn,
            epub_file=f"{epub_filename}.enc",
            cover_image=cover_image_filename,
            language=language,
            genre=genre,
            e_book_type=e_book_type,
            price=price,
            rental_price=rental_price,
            description=description,
            status=book_status
        )
        db.session.add(new_book)
        db.session.flush()

        new_file = File(
            publisher_id=publisher_id,
            book_id=new_book.book_id,
            file_path=f"{epub_filename}.enc"
        )
        db.session.add(new_file)
        db.session.commit()

        return jsonify({
            "message": "Book uploaded successfully",
            "book_id": new_book.book_id,
            "file_name": f"{epub_filename}.enc",
            "cover_image_name": cover_image_filename,
            "status": book_status
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# Helper function to check allowed image file extensions
def allowed_image(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


@book_bp.route('/pub/get_books_by_cat/<int:category_id>', methods=['GET'])
@jwt_required()
def get_books_by_cat(category_id):
    try:
        # Get publisher_id from JWT
        publisher_id = get_jwt_identity()

        # Verify category belongs to the publisher
        category = Category.query.filter_by(category_id=category_id, publisher_id=publisher_id).first()
        if not category:
            return jsonify({"error": "Invalid category ID"}), 404

        # Get all books for the given category
        books = Book.query.filter_by(category_id=category_id).all()

        # Serialize book data
        books_list = []
        for book in books:
            books_list.append({
                "book_id": book.book_id,
                "title": book.title,
                "author": book.author,
                "isbn": book.isbn,
                "language": book.language,
                "genre": book.genre,
                "e_book_type": book.e_book_type,
                "price": str(book.price),
                "rental_price": str(book.rental_price),
                "description": book.description,
                "created_at": book.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "updated_at": book.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            })

        return jsonify({
            "category_id": category_id,
            "category_name": category.category_name,
            "books": books_list
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@book_bp.route('/pub/get_book/<int:book_id>', methods=['GET'])
@jwt_required()
def get_book(book_id):
    try:
        # Get publisher_id from JWT
        publisher_id = get_jwt_identity()

        # Fetch the book details ensuring it belongs to the publisher
        book = Book.query.filter_by(book_id=book_id, publisher_id=publisher_id).first()

        if not book:
            return jsonify({"error": "Book not found"}), 404

        # Serialize book data
        book_details = {
            "book_id": book.book_id,
            "title": book.title,
            "author": book.author,
            "isbn": book.isbn,
            "language": book.language,
            "genre": book.genre,
            "e_book_type": book.e_book_type,
            "price": str(book.price),
            "rental_price": str(book.rental_price),
            "description": book.description,
            "created_at": book.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "updated_at": book.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            "epub_file": book.epub_file
        }
        return jsonify(book_details), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@book_bp.route('/pub/get_all_books', methods=['GET'])
@jwt_required()
def get_books():
    try:
        # Get publisher_id from JWT
        publisher_id = get_jwt_identity()

        # Fetch all books belonging to the publisher
        books = Book.query.filter_by(publisher_id=publisher_id).all()

        if not books:
            return jsonify({"error": "No books found for this publisher"}), 404

        # Serialize book data
        books_details = []
        for book in books:
            book_details = {
                "book_id": book.book_id,
                "title": book.title,
                "author": book.author,
                "isbn": book.isbn,
                "language": book.language,
                "genre": book.genre,
                "e_book_type": book.e_book_type,
                "price": str(book.price),
                "rental_price": str(book.rental_price),
                "description": book.description,
                "created_at": book.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "updated_at": book.updated_at.strftime('%Y-%m-%d %H:%M:%S')
            }

            books_details.append(book_details)

        return jsonify(books_details), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@book_bp.route('/pub/delete_book/<int:book_id>', methods=['DELETE'])
@jwt_required()
def delete_book(book_id):
    try:
        # Get publisher_id from JWT
        publisher_id = get_jwt_identity()

        # Check if book exists and belongs to the publisher
        book = Book.query.filter_by(book_id=book_id, publisher_id=publisher_id).first()

        if not book:
            return jsonify({"error": "Book not found or access denied"}), 404

        # Delete associated files from database and file system
        for file in book.files:
            # Delete the file from the file system
            if os.path.exists(file.file_path):
                os.remove(file.file_path)

            # Delete the file record from the database
            db.session.delete(file)

        # Delete book
        db.session.delete(book)
        db.session.commit()

        return jsonify({"message": "Book and associated files deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@files_bp.route('/pub/update_book/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    try:
        publisher_id = get_jwt_identity()

        book = Book.query.filter_by(book_id=book_id, publisher_id=publisher_id).first()
        if not book:
            return jsonify({"error": "Book not found"}), 404

        title = request.form.get('title', book.title)
        author = request.form.get('author', book.author)
        isbn = request.form.get('isbn', book.isbn)
        category_id = request.form.get('category_id', book.category_id)
        language = request.form.get('language', book.language)
        genre = request.form.get('genre', book.genre)
        e_book_type = request.form.get('e_book_type', book.e_book_type)
        price = request.form.get('price', book.price)
        rental_price = request.form.get('rental_price', book.rental_price)
        description = request.form.get('description', book.description)

        category = Category.query.filter_by(category_id=category_id, publisher_id=publisher_id).first()
        if not category:
            return jsonify({"error": "Invalid category ID"}), 400

        file_upload_folder = current_app.config['FILE_UPLOAD_FOLDER']
        image_upload_folder = current_app.config['IMAGE_UPLOAD_FOLDER']

        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                if allowed_file(file.filename):
                    file_ext = os.path.splitext(file.filename)[1]  # Get file extension
                    epub_filename = f"{book.book_id}{file_ext}"
                    encrypted_file_content = encrypt_file(file)

                    full_file_path = os.path.join(file_upload_folder, epub_filename + ".enc")
                    with open(full_file_path, 'wb') as f:
                        f.write(encrypted_file_content)

                    book.epub_file = f"{epub_filename}.enc"  # Store updated file name

                else:
                    return jsonify({"error": "Invalid file type"}), 400

        if 'cover_image' in request.files:
            cover_image = request.files['cover_image']
            if cover_image.filename:
                if allowed_file(cover_image.filename):
                    cover_ext = os.path.splitext(cover_image.filename)[1]
                    cover_image_filename = f"{book.book_id}{cover_ext}"
                    full_cover_image_path = os.path.join(image_upload_folder, cover_image_filename)

                    cover_image.save(full_cover_image_path)
                    book.cover_image = cover_image_filename  # Store only filename

                else:
                    return jsonify({"error": "Invalid cover image type"}), 400

        book.title = title
        book.author = author
        book.isbn = isbn
        book.category_id = category_id
        book.language = language
        book.genre = genre
        book.e_book_type = e_book_type
        book.price = price
        book.rental_price = rental_price
        book.description = description

        db.session.commit()

        return jsonify({
            "message": "Book updated successfully",
            "book_id": book.book_id,
            "file_name": book.epub_file,  # Return updated EPUB file name
            "cover_image_name": book.cover_image  # Return updated cover image name
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500



@auth.route('/reader/register', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit
def reader_register():
    data = request.json
    required_fields = ["name", "email", "password", "phone", 'geo_location', 'address']

    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    if Reader.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already registered"}), 400

    hashed_password = ph.hash(data['password'])

    new_reader = Reader(
        name=data['name'],
        email=data['email'],
        password=hashed_password,
        phone=data.get('phone'),
        geo_location=data.get('geo_location'),
        address=data.get('address')
    )
    db.session.add(new_reader)
    db.session.commit()

    return jsonify({"message": "Registration successful"}), 201


@auth.route('/reader/login', methods=['POST'])
@limiter.limit("10 per minute")
def reader_login():
    data = request.json
    reader = Reader.query.filter_by(email=data['email']).first()

    if not reader:
        return jsonify({"error": "Invalid email or password"}), 401

    try:
        if ph.verify(reader.password, data['password']):
            access_token = create_access_token(identity=str(reader.reader_id))
            return jsonify({"access_token": access_token, "message": "Login successful"}), 200
    except VerifyMismatchError:
        return jsonify({"error": "Invalid email or password"}), 401


@book_bp.route('/reader/add_highlight', methods=['POST'])
def add_highlight():
    data = request.json
    required_fields = ['book_id', 'text', 'highlight_range', 'color']

    # Check if all required fields are present
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    # Get reader_id from JWT token
    reader_id = get_jwt_identity()

    # Check if the reader exists
    reader = Reader.query.get(reader_id)
    if not reader:
        return jsonify({"error": "Reader not found"}), 404

    # Check if the book exists
    book = Book.query.get(data['book_id'])
    if not book:
        return jsonify({"error": "Book not found"}), 404

    # Create new highlight
    new_highlight = Highlight(
        reader_id=1,
        book_id=data['book_id'],
        text=data['text'],
        highlight_range=data['highlight_range'],
        color=data['color']
    )

    # Add highlight to database
    db.session.add(new_highlight)
    db.session.commit()

    return jsonify({
        "message": "Highlight added successfully",
        "highlight": {
            "hl_id": new_highlight.hl_id,
            "book_id": new_highlight.book_id,
            "text": new_highlight.text,
            "highlight_range": new_highlight.highlight_range,
            "color": new_highlight.color
        }
    }), 201


@book_bp.route('reader/get_highlights/<int:book_id>', methods=['GET'])
@jwt_required()
def get_highlights(book_id):
    try:
        # Get reader_id from JWT token
        reader_id = get_jwt_identity()

        # Check if the reader exists
        reader = Reader.query.get(reader_id)
        if not reader:
            return jsonify({"error": "Reader not found"}), 404



        # Check if the book exists
        book = Book.query.get(book_id)
        if not book:
            return jsonify({"error": "Book not found"}), 404

        # Fetch all highlights for the given reader_id and book_id
        highlights = Highlight.query.filter_by(reader_id=reader_id, book_id=book_id).all()

        # Serialize highlights data
        highlights_data = []
        for highlight in highlights:
            highlights_data.append({
                "text": highlight.text,
                "highlight_range": highlight.highlight_range,
                "color": highlight.color
            })

        return jsonify({
            "reader_id": reader_id,
            "book_id": book_id,
            "highlights": highlights_data
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@book_bp.route('/reader/add_note', methods=['POST'])
@jwt_required()
def add_note():
    data = request.json
    required_fields = ['book_id', 'text', 'note_range']

    # Check if all required fields are present
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    # Get reader_id from JWT token
    reader_id = get_jwt_identity()

    # Check if the reader exists
    reader = Reader.query.get(reader_id)
    if not reader:
        return jsonify({"error": "Reader not found"}), 404

    # Check if the book exists
    book = Book.query.get(data['book_id'])
    if not book:
        return jsonify({"error": "Book not found"}), 404

    # Create new note
    new_note = Note(
        reader_id=reader_id,
        book_id=data['book_id'],
        text=data['text'],
        note_range=data['note_range']
    )

    # Add note to database
    db.session.add(new_note)
    db.session.commit()

    return jsonify({
        "message": "Note added successfully",
        "note": {
            "note_id": new_note.note_id,
            "book_id": new_note.book_id,
            "text": new_note.text,
            "note_range": new_note.note_range
        }
    }), 201


@book_bp.route('/reader/get_notes/<int:book_id>', methods=['GET'])
@jwt_required()
def get_notes(book_id):
    try:
        # Get reader_id from JWT token
        reader_id = get_jwt_identity()

        # Check if the reader exists
        reader = Reader.query.get(reader_id)
        if not reader:
            return jsonify({"error": "Reader not found"}), 404

        # Check if the book exists
        book = Book.query.get(book_id)
        if not book:
            return jsonify({"error": "Book not found"}), 404

        # Fetch all notes for the given reader_id and book_id
        notes = Note.query.filter_by(reader_id=reader_id, book_id=book_id).all()

        # Serialize notes data
        notes_data = []
        for note in notes:
            notes_data.append({
                "text": note.text,
                "note_range": note.note_range
            })

        return jsonify({
            "reader_id": reader_id,
            "book_id": book_id,
            "notes": notes_data
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@book_bp.route('/reader/purchase_book', methods=['POST'])
@jwt_required()
def purchase_book():
    data = request.json
    required_fields = ['book_id']

    # Check if all required fields are present
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    # Get reader_id from JWT token (For now, assuming reader_id = 1)
    reader_id = get_jwt_identity()

    # Check if the reader exists
    reader = Reader.query.get(reader_id)
    if not reader:
        return jsonify({"error": "Reader not found"}), 404

    # Check if the book exists
    book = Book.query.get(data['book_id'])
    if not book:
        return jsonify({"error": "Book not found"}), 404

    # Check if the book is already purchased
    existing_purchase = BooksPurchased.query.filter_by(reader_id=reader_id, book_id=data['book_id'], bookmark=0).first()
    if existing_purchase:
        return jsonify({"error": "Book already purchased"}), 400

    # Create a new purchase record
    new_purchase = BooksPurchased(
        reader_id=reader_id,
        book_id=data['book_id'],
        bookmark=0  # Default bookmark at 0
    )

    # Add the purchase to the database
    db.session.add(new_purchase)
    db.session.commit()

    return jsonify({
        "message": "Book purchased successfully",
        "purchase": {
            "bp_id": new_purchase.bp_id,
            "book_id": new_purchase.book_id,
            "bookmark": new_purchase.bookmark
        }
    }), 201

@book_bp.route('/reader/get_purchased_books', methods=['GET'])
@jwt_required()
def get_purchased_books():
    try:
        # Get reader_id from JWT token
        reader_id = get_jwt_identity()

        # Check if the reader exists
        reader = Reader.query.get(reader_id)
        if not reader:
            return jsonify({"error": "Reader not found"}), 404

        # Fetch all purchased books for the given reader_id
        purchased_books = BooksPurchased.query.filter_by(reader_id=reader_id).all()

        # Serialize purchased books data
        books_data = []
        for purchase in purchased_books:
            book = Book.query.get(purchase.book_id)
            if book:
                books_data.append({
                    "book_id": book.book_id,
                    "title": book.title,
                    "author": book.author,
                    "isbn": book.isbn,
                    "cover_image": book.cover_image,
                    "file_path": book.epub_file,
                    "purchase_date": purchase.purchase_date,
                    "bookmark": purchase.bookmark
                })

        return jsonify({
            "reader_id": reader_id,
            "purchased_books": books_data
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@book_bp.route('/reader/get_book/<int:book_id>', methods=['GET'])
@jwt_required()
def get_reader_book(book_id):
    try:
        # Get publisher_id from JWT
        reader_id = get_jwt_identity()

        # Check if the reader exists
        reader = Reader.query.get(reader_id)
        if not reader:
            return jsonify({"error": "Reader not found"}), 404

        # Fetch the book details ensuring it belongs to the publisher
        book = Book.query.filter_by(book_id=book_id).first()

        if not book:
            return jsonify({"error": "Book not found"}), 404

        # Serialize book data
        book_details = {
            "book_id": book.book_id,
            "title": book.title,
            "author": book.author,
            "isbn": book.isbn,
            "file_path": book.epub_file,
            "cover_image": book.cover_image,
            "language": book.language,
            "genre": book.genre,
            "e_book_type": book.e_book_type,
            "price": str(book.price),
            "rental_price": str(book.rental_price),
            "created_at": book.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "updated_at": book.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        return jsonify(book_details), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@book_bp.route('/reader/add_cart', methods=['POST'])
@jwt_required()
def add_to_cart():
    data = request.json
    reader_id = get_jwt_identity()
    book_id = data.get('book_id')

    if not book_id:
        return jsonify({"error": "Book ID is required"}), 400

    # Check if the book exists
    book = Book.query.get(book_id)
    if not book:
        return jsonify({"error": "Book not found"}), 404

    # Add to cart
    new_cart_item = Cart(reader_id=reader_id, book_id=book_id)
    db.session.add(new_cart_item)
    db.session.commit()

    return jsonify({"message": "Book added to cart successfully"}), 201


@book_bp.route('reader/get_cart', methods=['GET'])
@jwt_required()
def get_cart():
    reader_id = get_jwt_identity()
    cart_items = Cart.query.filter_by(reader_id=reader_id).all()

    return jsonify({
        "cart": [
            {
                "cart_id": item.cart_id,
                "book_id": item.book.book_id,
                "title": item.book.title,
                "author": item.book.author,
                "added_at": item.added_at.strftime('%Y-%m-%d %H:%M:%S')
            }
            for item in cart_items
        ]
    }), 200


@book_bp.route('reader/delete_cart/<int:cart_id>', methods=['DELETE'])
@jwt_required()
def delete_cart(cart_id):
    try:
        reader_id = get_jwt_identity()

        # Check if the cart item exists
        cart_item = Cart.query.filter_by(cart_id=cart_id, reader_id=reader_id).first()
        if not cart_item:
            return jsonify({"error": "Cart item not found"}), 404

        # Delete the item
        db.session.delete(cart_item)
        db.session.commit()

        return jsonify({"message": "Cart item deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@book_bp.route('/reader/add_wishlist', methods=['POST'])
@jwt_required()
def add_to_wishlist():
    data = request.json
    reader_id = get_jwt_identity()
    book_id = data.get('book_id')

    if not book_id:
        return jsonify({"error": "Book ID is required"}), 400

    # Check if the book exists
    book = Book.query.get(book_id)
    if not book:
        return jsonify({"error": "Book not found"}), 404

    # Add to wishlist
    new_wishlist_item = Wishlist(reader_id=reader_id, book_id=book_id)
    db.session.add(new_wishlist_item)
    db.session.commit()

    return jsonify({"message": "Book added to wishlist successfully"}), 201


@book_bp.route('/reader/get_wishlist', methods=['GET'])
@jwt_required()
def get_wishlist():
    reader_id = get_jwt_identity()
    wishlist_items = Wishlist.query.filter_by(reader_id=reader_id).all()

    return jsonify({
        "wishlist": [
            {
                "wishlist_id": item.wishlist_id,
                "book_id": item.book.book_id,
                "title": item.book.title,
                "author": item.book.author,
                "added_at": item.added_at.strftime('%Y-%m-%d %H:%M:%S')
            }
            for item in wishlist_items
        ]
    }), 200


@book_bp.route('/reader/delete_wishlist/<int:wishlist_id>', methods=['DELETE'])
@jwt_required()
def delete_wishlist(wishlist_id):
    try:
        reader_id = get_jwt_identity()

        # Check if the wishlist item exists
        wishlist_item = Wishlist.query.filter_by(wishlist_id=wishlist_id, reader_id=reader_id).first()
        if not wishlist_item:
            return jsonify({"error": "Wishlist item not found"}), 404

        # Delete the item
        db.session.delete(wishlist_item)
        db.session.commit()

        return jsonify({"message": "Wishlist item deleted successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@book_bp.route('/stream/<filename>')
@jwt_required()
def serve_epub(filename):
    file_path = os.path.join(current_app.config['FILE_UPLOAD_FOLDER'], filename)

    if os.path.exists(file_path):
        return send_file(file_path)
    else:
        abort(404, description="File not found")