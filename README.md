python3.8  glued-v3.py  -e --input 12345.txt  --output 1245.dat -p P@ssword1 --key test.key

python3 send_email.py --to recipient@example.com --subject "Test Email" --content "This is a test email." --attachment /path/to/your/attachment


mailer_v4
python3 send_email.py --to recipient@example.com --subject "Test Email" --content "Hey, check this out!" --attachment "/path/to/file.txt"

--content: The content you want to prepend (this gets combined with the default text from default_email.txt).

++++++++++++++++


This script is a secure file encryption and decryption tool that uses AES-GCM for encrypting file contents and Argon2 for deriving encryption keys from a user-supplied passphrase. When encrypting, it generates a random 256-bit file key to encrypt the input file, then derives a master key from the user's passphrase and a random salt using Argon2. 

The file key is encrypted using the master key and stored in a separate key file alongside the salt and AES-GCM nonce. The original unencrypted file is securely deleted after encryption to prevent data leakage. When decrypting, the script reads the key file to extract the salt, nonce, and encrypted file key, re-derives the master key using the passphrase and salt, and decrypts the file key, which is then used to decrypt the encrypted file. 

Decryption is only possible if the correct passphrase is provided and both the encrypted file and the key file are intact, ensuring that unauthorized access is effectively prevented through strong enc
