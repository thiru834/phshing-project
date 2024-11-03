from flask import Flask, render_template, request
import pickle
import numpy as np
import tldextract
import re
import socket

app = Flask(__name__)

# Load the pre-trained model
with open(r'D:\mini project sr\XGBoostClassifier.pickle.dat', 'rb') as model_file:
    model = pickle.load(model_file)

# Helper function to check DNS records
def has_dns_record(url):
    domain = tldextract.extract(url).domain
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

# Feature extraction function
import whois
from datetime import datetime

# Function to check if a URL has high traffic (placeholder logic)
def is_high_traffic(url):
    # This function could check against a database or API for traffic data.
    # For now, let's assume it returns False for all URLs.
    # You can replace this logic with actual traffic checking.
    return False

# Function to get the age of a domain (placeholder logic)
def get_domain_age(url):
    domain = tldextract.extract(url).domain
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):  # Handling cases where creation_date is a list
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days / 365  # Calculate age in years
        return int(age) if age > 0 else 0
    except Exception as e:
        return 0  # Return 0 if unable to fetch domain age

def featureExtraction(url):
    features = []
    
    # 1. Have_IP
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)
    
    # 2. Have_At
    features.append(1 if "@" in url else 0)

    # 3. URL_Length
    features.append(len(url))

    # 4. URL_Depth
    features.append(url.count('/') - 2)  # Adjust depending on how you define URL depth

    # 5. Redirection
    features.append(1 if url.count('redirect') > 0 else 0)

    # 6. https_Domain
    features.append(1 if url.startswith("https") else 0)

    # 7. TinyURL
    features.append(1 if "tinyurl" in url or "bit.ly" in url else 0)

    # 8. Prefix/Suffix
    features.append(1 if "-" in tldextract.extract(url).domain else 0)

    # 9. DNS_Record
    features.append(1 if has_dns_record(url) else 0)

    # 10. Web_Traffic
    features.append(1 if is_high_traffic(url) else 0)  # Placeholder, define this function

    # 11. Domain_Age
    features.append(get_domain_age(url))  # Placeholder, define this function

    # 12. Domain_End
    features.append(1 if url.endswith('.com') else 0)  # Adjust according to your criteria

    # 13. iFrame
    features.append(1 if "iframe" in url else 0)  # Placeholder logic

    # 14. Mouse_Over
    features.append(1 if "mouseover" in url else 0)  # Placeholder logic

    # 15. Right_Click
    features.append(1 if "rightclick" in url else 0)  # Placeholder logic

    # 16. Web_Forwards
    features.append(1 if "forward" in url else 0)  # Placeholder logic

    return features

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features = featureExtraction(url)
    features_array = np.array(features).reshape(1, -1)

    # Predict using the loaded model
    prediction = model.predict(features_array)[0]
    result = "Phishing" if prediction == 1 else "Legitimate"
    
    return render_template('index.html', url=url, result=result)

if __name__ == "__main__":
    app.run(debug=True)
