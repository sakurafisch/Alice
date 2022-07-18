import hashlib

def main() -> None:
    with open("pk.crt", "r") as file:
        content = file.read()
        sha1 = hashlib.sha1(content.encode('utf-8'), usedforsecurity=True)
        hashed_content = sha1.hexdigest()

        with open("pk.crt.hashed.txt", "w") as output_file:
            output_file.write(hashed_content)

if __name__ == '__main__':
    main()
