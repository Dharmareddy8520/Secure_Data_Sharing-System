# main.py
from abe_crypto import ABECrypto

def main():
    abe = ABECrypto()
    while True:
        print("\nSecure Data Sharing System")
        print("1. Issue AC")
        print("2. Encrypt Data")
        print("3. Decrypt Data")
        print("4. Revoke Attribute")
        print("5. Exit")
        choice = input("Enter choice: ")

        try:
            if choice == '1':
                user_id = input("Enter User ID: ")
                attributes = input("Enter attributes (comma-separated): ").split(',')
                attributes = [attr.strip() for attr in attributes if attr.strip()]
                if not user_id or not attributes:
                    print("User ID and attributes are required.")
                    continue
                ac = abe.issue_ac(user_id, attributes)
                print(f"AC Issued: {ac}")

            elif choice == '2':
                message = input("Enter message: ")
                policy = input("Enter policy (e.g., 'Engineer and Dept_A'): ")
                if not message or not policy:
                    print("Message and policy are required.")
                    continue
                data_id = abe.encrypt(message, policy)
                print(f"Data encrypted with ID: {data_id}")

            elif choice == '3':
                user_id = input("Enter User ID: ")
                data_id = input("Enter Data ID: ")
                if not user_id or not data_id:
                    print("User ID and Data ID are required.")
                    continue
                message = abe.decrypt(user_id, data_id)
                print(f"Decrypted Message: {message}")

            elif choice == '4':
                user_id = input("Enter User ID: ")
                attribute = input("Enter attribute to revoke: ")
                if not user_id or not attribute:
                    print("User ID and attribute to revoke are required.")
                    continue
                new_ac = abe.revoke_attribute(user_id, attribute)
                print(f"Updated AC: {new_ac}")

            elif choice == '5':
                print("Exiting...")
                break

            else:
                print("Invalid choice. Please enter a number between 1 and 5.")

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()