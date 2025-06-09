# app.py
# -*- coding: utf-8 -*-
#Author: koyyada vishnu vardhan
# Date: 2023-10-01
# Description: Flask application for YugabyteDB with JWT authentication and CRUD operations.
# License: MIT License

import os
import random
import string
from datetime import datetime
from functools import wraps

import jwt
from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://yugabyte:yugabyte@yb-tservers.yugabyte.svc.cluster.local:5433/yugabyte')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Connection pool settings for SQLAlchemy
app.config['SQLALCHEMY_POOL_SIZE'] = 20
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 40
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800

db = SQLAlchemy(app)

# Models (same as your original)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100))
    sales = db.Column(db.Integer, default=0)
    sales_sum = db.Column(db.Float, default=0.0)
    purchases = db.Column(db.Integer, default=0)
    purchases_sum = db.Column(db.Float, default=0.0)
    balance = db.Column(db.Float, default=0.0)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'sales': self.sales,
            'sales_sum': self.sales_sum,
            'purchases': self.purchases,
            'purchases_sum': self.purchases_sum,
            'balance': self.balance
        }

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    manufacturer = db.Column(db.String(100))
    sales = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'manufacturer': self.manufacturer,
            'sales': self.sales
        }

class Sale(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    seller_uid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    buyer_uid = db.Column(db.Integer, db.ForeignKey('user.id'))
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    date_offered = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_sold = db.Column(db.DateTime)

    seller = db.relationship('User', foreign_keys=[seller_uid], backref='sales_as_seller')
    buyer = db.relationship('User', foreign_keys=[buyer_uid], backref='sales_as_buyer')
    item = db.relationship('Item', backref='associated_sales')

    def to_dict(self):
        return {
            'id': self.id,
            'seller_uid': self.seller_uid,
            'buyer_uid': self.buyer_uid,
            'item_id': self.item_id,
            'price': self.price,
            'date_offered': self.date_offered.isoformat() if self.date_offered else None,
            'date_sold': self.date_sold.isoformat() if self.date_sold else None,
            'item': self.item.to_dict() if self.item else None,
            'seller': self.seller.to_dict() if self.seller else None,
            'buyer': self.buyer.to_dict() if self.buyer else None
        }

# Helper functions
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

def random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Routes
@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'message': 'Email and password required'}), 401
    
    user = User.query.filter_by(email=auth['email']).first()
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401
    
    if check_password_hash(user.password, auth['password']):
        token = jwt.encode({'user_id': user.id}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/user/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    return jsonify(user.to_dict())

@app.route('/user/<int:user_id>/sales', methods=['GET'])
@token_required
def list_sales(current_user, user_id):
    if not User.query.get(user_id):
        return jsonify({'message': 'User not found'}), 404
    
    query = Sale.query.filter_by(seller_uid=user_id).filter(Sale.buyer_uid.isnot(None))
    
    # Apply filters
    if 'item_title' in request.args:
        query = query.join(Item).filter(Item.title.ilike(f"%{request.args['item_title']}%"))
    if 'seller_desc' in request.args:
        query = query.join(User, Sale.seller_uid == User.id).filter(User.name.ilike(f"%{request.args['seller_desc']}%"))
    if 'manufacturer_desc' in request.args:
        query = query.join(Item).filter(Item.manufacturer.ilike(f"%{request.args['manufacturer_desc']}%"))
    
    sales = query.order_by(Sale.date_offered.desc()).all()
    return jsonify([sale.to_dict() for sale in sales])

@app.route('/user/<int:user_id>/purchases', methods=['GET'])
@token_required
def list_purchases(current_user, user_id):
    if not User.query.get(user_id):
        return jsonify({'message': 'User not found'}), 404
    
    query = Sale.query.filter_by(buyer_uid=user_id)
    
    # Apply filters
    if 'item_title' in request.args:
        query = query.join(Item).filter(Item.title.ilike(f"%{request.args['item_title']}%"))
    if 'seller_desc' in request.args:
        query = query.join(User, Sale.seller_uid == User.id).filter(User.name.ilike(f"%{request.args['seller_desc']}%"))
    if 'manufacturer_desc' in request.args:
        query = query.join(Item).filter(Item.manufacturer.ilike(f"%{request.args['manufacturer_desc']}%"))
    
    purchases = query.order_by(Sale.date_offered.desc()).all()
    return jsonify([sale.to_dict() for sale in purchases])

@app.route('/user/<int:user_id>/offers', methods=['GET'])
@token_required
def list_user_offers(current_user, user_id):
    if not User.query.get(user_id):
        return jsonify({'message': 'User not found'}), 404
    
    offers = Sale.query.filter_by(seller_uid=user_id, buyer_uid=None).all()
    return jsonify([sale.to_dict() for sale in offers])

@app.route('/offers', methods=['GET'])
@token_required
def list_offers(current_user):
    offers = Sale.query.filter_by(buyer_uid=None).limit(100).all()
    return jsonify([sale.to_dict() for sale in offers])

@app.route('/offer', methods=['POST'])
@token_required
def create_offer(current_user):
    try:
        # Create a new item with random values
        item = Item(
            title=random_string(15),
            description=random_string(50),
            manufacturer=random_string(10),
            sales=0
        )
        db.session.add(item)
        db.session.flush()  # Get the item ID
        
        # Create the offer
        offer = Sale(
            seller_uid=current_user.id,
            buyer_uid=None,
            item_id=item.id,
            price=round(random.uniform(10, 1000), 2),
            date_offered=datetime.utcnow(),
            date_sold=None
        )
        db.session.add(offer)
        db.session.commit()
        
        return jsonify(offer.to_dict()), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to create offer', 'error': str(e)}), 500

@app.route('/offer/<int:sale_id>/buy', methods=['PUT'])
@token_required
def buy_offer(current_user, sale_id):
    sale = Sale.query.get(sale_id)
    if not sale:
        return jsonify({'message': 'Sale not found'}), 404
    
    if sale.seller_uid == current_user.id:
        return jsonify({'message': 'You cannot buy your own offer'}), 403
    
    if sale.buyer_uid is not None:
        return jsonify({'message': 'This item has already been sold'}), 400
    
    # Start transaction
    try:
        # Update sale record
        sale.buyer_uid = current_user.id
        sale.date_sold = datetime.utcnow()
        
        # Update item sales count
        sale.item.sales += 1
        
        # Update seller stats
        seller = User.query.get(sale.seller_uid)
        seller.sales += 1
        seller.sales_sum += sale.price
        seller.balance += sale.price
        
        # Update buyer stats
        current_user.purchases += 1
        current_user.purchases_sum += sale.price
        current_user.balance -= sale.price
        
        db.session.commit()
        
        return jsonify(sale.to_dict())
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Transaction failed', 'error': str(e)}), 500

@app.route('/offer/<int:sale_id>', methods=['DELETE'])
@token_required
def delete_offer(current_user, sale_id):
    sale = Sale.query.get(sale_id)
    if not sale:
        return jsonify({'message': 'Sale not found'}), 404
    
    if sale.seller_uid != current_user.id:
        return jsonify({'message': 'You can only delete your own offers'}), 403
    
    if sale.buyer_uid is not None:
        return jsonify({'message': 'Cannot delete a completed sale'}), 400
    
    try:
        # Also delete the associated item if it was created for this offer
        item = sale.item
        db.session.delete(sale)
        if item and item.sales == 0:  # Only delete if no sales occurred
            db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Offer deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to delete offer', 'error': str(e)}), 500

@app.route('/health')
def health_check():
    return 'OK', 200

# Add these helper endpoints for load testing
@app.route('/check-balance-consistency')
def check_balance_consistency():
    try:
        total_balance = db.session.query(db.func.sum(User.balance)).scalar() or 0
        return jsonify({
            'total_balance': float(total_balance),
            'is_consistent': abs(total_balance) < 0.01
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/test-stats')
def test_stats():
    try:
        user_count = User.query.count()
        offer_count = Sale.query.filter_by(buyer_uid=None).count()
        completed_sales = Sale.query.filter(Sale.buyer_uid.isnot(None)).count()
        
        return jsonify({
            'total_users': user_count,
            'active_offers': offer_count,
            'completed_sales': completed_sales
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(401)
def unauthorized_error(e):
    return jsonify({'message': 'Unauthorized access'}), 401

@app.errorhandler(403)
def forbidden_error(e):
    return jsonify({'message': 'Forbidden'}), 403

@app.errorhandler(404)
def not_found_error(e):
    return jsonify({'message': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'message': 'Internal server error'}), 500

# Database initialization

with app.app_context():
    db.create_all()
    
    # Create 1000 test users for load testing
    print("Checking/Creating test users...")
    created_count = 0
    
    # Get all existing emails first to minimize database queries in the loop
    existing_emails = {user.email for user in User.query.with_entities(User.email).all()}
    
    for i in range(1, 1001):
        email = f"user{i}@example.com"
        if email not in existing_emails:
            try:
                user = User(
                    email=email,
                    password=generate_password_hash(f"password{i}"),
                    name=f"Test User {i}",
                    balance=1000.0  # Give users starting balance for transactions
                )
                db.session.add(user)
                created_count += 1
                
                # Commit each user individually to avoid transaction conflicts
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                print(f"Error creating user {email}: {str(e)}")
                continue
    
    print(f"Total users created: {created_count}")
    
    # Create some initial offers for testing
    offer_count = Sale.query.filter_by(buyer_uid=None).count()
    if offer_count < 50:
        print("Creating initial offers...")
        # Get all users at once
        users = User.query.all()
        if users:
            for i in range(50):
                try:
                    user = random.choice(users)
                    item = Item(
                        title=f"Test Item {random_string(10)}",
                        description=f"Test Description {random_string(20)}",
                        manufacturer=f"Test Manufacturer {random_string(5)}",
                        sales=0
                    )
                    db.session.add(item)
                    db.session.flush()
                    
                    offer = Sale(
                        seller_uid=user.id,
                        buyer_uid=None,
                        item_id=item.id,
                        price=round(random.uniform(10, 500), 2),
                        date_offered=datetime.utcnow()
                    )
                    db.session.add(offer)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    print(f"Error creating offer: {str(e)}")
                    continue
        
        print("Initial offers created.")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)