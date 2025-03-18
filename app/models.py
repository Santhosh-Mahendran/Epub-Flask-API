from .extensions import db
from datetime import datetime


class Publisher(db.Model):
    __tablename__ = 'publisher'
    publisher_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    password = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, nullable=False)
    geo_location = db.Column(db.String)
    address = db.Column(db.String)
    signup_date = db.Column(db.Date, default=datetime.utcnow)

    # Relationships
    categories = db.relationship('Category', backref='publisher', lazy=True)
    books = db.relationship('Book', backref='publisher', lazy=True)
    files = db.relationship('File', backref='publisher', lazy=True)


class Category(db.Model):
    __tablename__ = 'category'
    category_id = db.Column(db.Integer, primary_key=True)
    publisher_id = db.Column(db.Integer, db.ForeignKey('publisher.publisher_id'), nullable=False)
    category_name = db.Column(db.String, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.Date)
    updated_time = db.Column(db.Date)

    # Relationship
    books = db.relationship('Book', backref='category', lazy=True)


class Book(db.Model):
    __tablename__ = 'book'
    book_id = db.Column(db.Integer, primary_key=True)
    publisher_id = db.Column(db.Integer, db.ForeignKey('publisher.publisher_id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.category_id'), nullable=False)
    title = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)
    isbn = db.Column(db.String, nullable=False)
    epub_file = db.Column(db.String)
    cover_image = db.Column(db.String)
    language = db.Column(db.String)
    genre = db.Column(db.String)
    e_book_type = db.Column(db.String)
    price = db.Column(db.Numeric)
    rental_price = db.Column(db.Numeric)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    files = db.relationship('File', backref='book', lazy=True)


class File(db.Model):
    __tablename__ = 'files'
    file_id = db.Column(db.Integer, primary_key=True)
    publisher_id = db.Column(db.Integer, db.ForeignKey('publisher.publisher_id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id'), nullable=False)
    file_path = db.Column(db.String, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class Reader(db.Model):
    __tablename__ = 'reader'
    reader_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    phone = db.Column(db.String, nullable=False)
    geo_location = db.Column(db.String)
    address = db.Column(db.String)
    signup_date = db.Column(db.Date, default=datetime.utcnow)




class Highlight(db.Model):
    __tablename__ = 'highlights'

    hl_id = db.Column(db.Integer, primary_key=True)
    reader_id = db.Column(db.Integer, db.ForeignKey('reader.reader_id', ondelete='CASCADE'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    highlight_range = db.Column(db.String(255), nullable=False)
    color = db.Column(db.String(20), nullable=False, default='yellow')

    # Relationships
    reader = db.relationship('Reader', backref=db.backref('highlights', lazy=True, cascade="all, delete"))
    book = db.relationship('Book', backref=db.backref('highlights', lazy=True, cascade="all, delete"))


class Note(db.Model):
    __tablename__ = 'notes'

    note_id = db.Column(db.Integer, primary_key=True)
    reader_id = db.Column(db.Integer, db.ForeignKey('reader.reader_id', ondelete='CASCADE'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    note_range = db.Column(db.String(255), nullable=False)

    # Relationships
    reader = db.relationship('Reader', backref=db.backref('notes', lazy=True, cascade="all, delete"))
    book = db.relationship('Book', backref=db.backref('notes', lazy=True, cascade="all, delete"))


class BooksPurchased(db.Model):
    __tablename__ = 'books_purchased'

    bp_id = db.Column(db.Integer, primary_key=True)  # Primary Key
    reader_id = db.Column(db.Integer, db.ForeignKey('reader.reader_id'), nullable=False)  # Foreign Key to Reader
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id'), nullable=False)  # Foreign Key to Book
    bookmark = db.Column(db.Integer, default=0)  # Bookmark (0 to 100)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)  # Purchase Timestamp

    # Relationships (optional)
    reader = db.relationship('Reader', backref='purchases', lazy=True)
    book = db.relationship('Book', backref='purchases', lazy=True)

class Cart(db.Model):
    __tablename__ = 'cart'
    cart_id = db.Column(db.Integer, primary_key=True)
    reader_id = db.Column(db.Integer, db.ForeignKey('reader.reader_id', ondelete='CASCADE'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.book_id', ondelete='CASCADE'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    reader = db.relationship('Reader', backref=db.backref('carts', lazy=True))
    book = db.relationship('Book', backref=db.backref('carts', lazy=True))