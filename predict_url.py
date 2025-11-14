import joblib
from feature_extraction.feature_extractor import extract_url_features

# Load the trained model
model = joblib.load("trained_models/randomForest_final.pkl")

def predict_url(url):
    features = extract_url_features(url)
    prediction = model.predict([features])[0]
    label = "Phish" if prediction == 1 else "Safe"
    return label
