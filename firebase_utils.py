# firebase_utils.py
import firebase_admin
from firebase_admin import credentials, firestore

class FirebaseUtils:
    def __init__(self, cred_path):
        cred = credentials.Certificate(cred_path)
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        self.db = firestore.client()

    def store_user(self, user_id, attributes, ac, encrypted_sk=None):
        self.db.collection('users').document(user_id).set({
            'attributes': attributes,
            'ac': ac,
            'encrypted_sk': encrypted_sk if encrypted_sk else ''
        })

    def get_user(self, user_id):
        doc = self.db.collection('users').document(user_id).get()
        if doc.exists:
            return doc.to_dict()
        raise Exception("User not found.")

    def store_data(self, data_id, encrypted_data, iv, encrypted_key, policy):
        self.db.collection('data').document(data_id).set({
            'encrypted_data': encrypted_data,
            'iv': iv,
            'encrypted_key': encrypted_key,
            'policy': policy
        })

    def get_data(self, data_id):
        doc = self.db.collection('data').document(data_id).get()
        if doc.exists:
            return doc.to_dict()
        raise Exception("Data not found.")