# accpabe.py
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from firebase_utils import FirebaseUtils
from config import FIREBASE_CRED_PATH
import hashlib
import base64

class ACCPABE:
    def __init__(self):
        self.group = PairingGroup('SS512')  # Pairing curve
        self.cpabe = CPabe_BSW07(self.group)
        self.firebase = FirebaseUtils(FIREBASE_CRED_PATH)
        self.pk, self.mk = self.cpabe.setup()  # Public and master keys

    def issue_ac(self, user_id, attributes):
        """Issue an AC and CP-ABE secret key."""
        sk = self.cpabe.keygen(self.pk, self.mk, attributes)
        udk = hashlib.sha256(str(sk).encode()).hexdigest()[:16]
        ac = {
            'user_id': user_id,
            'attributes': attributes,
            'udk': udk,
            'validity': '2025-12-31',
            'signature': hashlib.sha256(udk.encode()).hexdigest()
        }
        sk_serialized = base64.b64encode(self.group.serialize(sk)).decode('utf-8')
        self.firebase.store_user(user_id, attributes, ac, sk_serialized)
        return ac

    def encrypt(self, message, policy):
        """Encrypt message with CP-ABE policy."""
        msg_bytes = message.encode()
        ciphertext = self.cpabe.encrypt(self.pk, self.group.encode(msg_bytes), policy)
        data_id = hashlib.sha256(msg_bytes).hexdigest()
        ct_serialized = base64.b64encode(self.group.serialize(ciphertext)).decode('utf-8')
        try:
            self.firebase.store_data(data_id, ct_serialized, policy)
            return data_id
        except Exception as e:
            raise Exception(f"Failed to store data: {e}")

    def decrypt(self, user_id, data_id):
        """Decrypt data if attributes satisfy policy."""
        user_data = self.firebase.get_user(user_id)
        ac = user_data.get('ac')
        sk_serialized = user_data.get('sk')
        sk = self.group.deserialize(base64.b64decode(sk_serialized))
        if not ac or hashlib.sha256(ac['udk'].encode()).hexdigest() != ac['signature']:
            raise Exception("Invalid AC.")
        
        ciphertext_data = self.firebase.get_data(data_id)
        ct_serialized = ciphertext_data['ciphertext']
        ciphertext = self.group.deserialize(base64.b64decode(ct_serialized))
        decrypted = self.cpabe.decrypt(self.pk, sk, ciphertext)
        if decrypted:
            return self.group.decode(decrypted).decode()
        raise Exception("Attributes do not satisfy policy.")

    def delegate_key_update(self, user_id, new_attributes):
        """Simulated delegated key update (re-issue key)."""
        return self.issue_ac(user_id, new_attributes)

    def revoke_attribute(self, user_id, attribute_to_revoke):
        """Revoke an attribute and update key."""
        user_data = self.firebase.get_user(user_id)
        current_attributes = user_data['attributes']
        if attribute_to_revoke not in current_attributes:
            raise Exception("Attribute not assigned.")
        
        updated_attributes = [attr for attr in current_attributes if attr != attribute_to_revoke]
        return self.delegate_key_update(user_id, updated_attributes)