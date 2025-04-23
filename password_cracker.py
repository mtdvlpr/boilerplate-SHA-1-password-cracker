import hashlib

def crack_sha1_hash(hash, use_salts=False):
    with open('top-10000-passwords.txt', 'r') as file:
        passwords = [line.strip() for line in file]

    if use_salts:
        with open('known-salts.txt', 'r') as file:
            salts = [line.strip() for line in file]

        for password in passwords:
            for salt in salts:
                salted_hash = hashlib.sha1((salt + password).encode()).hexdigest()
                if salted_hash == hash:
                    return password
                salted_hash = hashlib.sha1((password + salt).encode()).hexdigest()
                if salted_hash == hash:
                    return password
    else:
        for password in passwords:
            hashed_password = hashlib.sha1(password.encode()).hexdigest()
            if hashed_password == hash:
                return password

    return "PASSWORD NOT IN DATABASE"
