# Secure Data Sharing System

## Overview

The Secure Data Sharing System is a Python-based application designed to facilitate secure data sharing using Attribute-Based Encryption (ABE). This system ensures that data access is governed by user attributes and predefined policies. By leveraging RSA for key encryption and AES for data encryption, it guarantees both confidentiality and integrity of the shared data.

Key highlights include seamless integration with Firebase Firestore for storing user attributes, access credentials (ACs), and encrypted messages. The system also features a user-friendly graphical interface built with Tkinter, enabling users to manage access credentials, encrypt/decrypt data, and dynamically revoke attributes as needed. This robust solution is ideal for scenarios requiring fine-grained access control and secure data sharing.

## Key Features

- **Attribute-Based Encryption (ABE):** Data access is controlled by policies defined as conjunctions of attributes (e.g., `motel` and `emp`).
- **Secure Encryption:** Uses RSA for key encryption and AES for data encryption.
- **Firebase Integration:** Stores user data, ACs, and encrypted messages in Firebase Firestore.
- **GUI Interface:** A user-friendly Tkinter-based GUI for interacting with the system.
- **Attribute Revocation:** Supports revoking attributes from users, updating their access rights dynamically.
- **Error Handling:** Robust validation and error handling for edge cases (e.g., empty inputs, invalid policies).
- **Logging:** Outputs logs to both the GUI and terminal for debugging and monitoring.

## Prerequisites

Before setting up the project, ensure you have the following:

- **Python 3.8+:** The project is built using Python.
- **Firebase Account:** A Firebase project with Firestore enabled for data storage.
- **PowerShell:** For activating the virtual environment on Windows (optional but recommended).
- **Git:** For cloning the repository (optional).

## Setup Instructions

### 1. Clone the Repository

Clone the project repository to your local machine:

```bash
git clone https://github.com/Dharmareddy8520/Secure_Data_Sharing-System
cd secure-data-sharing
```

### 2. Set Up a Virtual Environment

Create and activate a virtual environment:

- On Windows:
  ```bash
  python -m venv venv
  .\venv\Scripts\activate
  ```
- On macOS/Linux:
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### 3. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

### 4. Configure Firebase

- Create a Firebase project and enable Firestore.
- Download the `serviceAccountKey.json` file from Firebase and place it in the project directory.
- Update the Firebase configuration in the `config.py` file.

### 5. Run the Application

Start the application:

```bash
python main.py
```

## Usage

1. **Launch the GUI:** Run the application to open the Tkinter-based interface.
2. **Manage Access Credentials:** Add, update, or revoke user attributes and policies.
3. **Encrypt Data:** Use the GUI to encrypt data based on attribute-based policies.
4. **Decrypt Data:** Decrypt data by providing the correct access credentials.
5. **Monitor Logs:** View logs in the GUI or terminal for debugging and monitoring.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Commit your changes and push the branch.
4. Open a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- The developers of PyCrypto and PyCryptodome for encryption libraries.
- Firebase for providing a robust backend solution.
- The Python community for their invaluable resources and support.
