#!/usr/bin/env python3
"""
Initialize Stripe products and prices for the application
"""
import os
import sys
import stripe

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def init_stripe_products():
    """Create Stripe products and prices if they don't exist"""
    stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
    
    if not stripe.api_key:
        print("Error: STRIPE_SECRET_KEY not set")
        return
    
    products = [
        {
            "name": "Basic Plan",
            "description": "Perfect for individual agents",
            "metadata": {"plan_name": "basic"},
            "prices": [
                {
                    "unit_amount": 2999,  # $29.99
                    "currency": "usd",
                    "recurring": {"interval": "month"},
                    "metadata": {"billing_period": "monthly"}
                },
                {
                    "unit_amount": 29999,  # $299.99 (save ~16%)
                    "currency": "usd",
                    "recurring": {"interval": "year"},
                    "metadata": {"billing_period": "yearly"}
                }
            ]
        },
        {
            "name": "Professional Plan",
            "description": "For growing real estate teams",
            "metadata": {"plan_name": "pro"},
            "prices": [
                {
                    "unit_amount": 7999,  # $79.99
                    "currency": "usd",
                    "recurring": {"interval": "month"},
                    "metadata": {"billing_period": "monthly"}
                },
                {
                    "unit_amount": 79999,  # $799.99 (save ~16%)
                    "currency": "usd",
                    "recurring": {"interval": "year"},
                    "metadata": {"billing_period": "yearly"}
                }
            ]
        },
        {
            "name": "Enterprise Plan",
            "description": "For large agencies and brokerages",
            "metadata": {"plan_name": "enterprise"},
            "prices": [
                {
                    "unit_amount": 19999,  # $199.99
                    "currency": "usd",
                    "recurring": {"interval": "month"},
                    "metadata": {"billing_period": "monthly"}
                },
                {
                    "unit_amount": 199999,  # $1999.99 (save ~16%)
                    "currency": "usd",
                    "recurring": {"interval": "year"},
                    "metadata": {"billing_period": "yearly"}
                }
            ]
        }
    ]
    
    created_products = []
    
    for product_data in products:
        try:
            # Check if product already exists
            existing_products = stripe.Product.list(limit=100)
            existing_product = None
            
            for prod in existing_products.auto_paging_iter():
                if prod.name == product_data["name"]:
                    existing_product = prod
                    break
            
            if existing_product:
                print(f"Product already exists: {existing_product.name} (id: {existing_product.id})")
                product = existing_product
            else:
                # Create product
                product = stripe.Product.create(
                    name=product_data["name"],
                    description=product_data["description"],
                    metadata=product_data["metadata"]
                )
                print(f"Created product: {product.name} (id: {product.id})")
            
            # Create prices
            for price_data in product_data["prices"]:
                price = stripe.Price.create(
                    product=product.id,
                    unit_amount=price_data["unit_amount"],
                    currency=price_data["currency"],
                    recurring=price_data["recurring"],
                    metadata=price_data["metadata"]
                )
                print(f"  Created price: ${price.unit_amount/100:.2f}/{price.recurring.interval} (id: {price.id})")
            
            created_products.append({
                "product": product,
                "prices": product_data["prices"]
            })
            
        except Exception as e:
            print(f"Error creating product {product_data['name']}: {str(e)}")
    
    return created_products

if __name__ == "__main__":
    print("Initializing Stripe products and prices...")
    init_stripe_products()
    print("Done!")