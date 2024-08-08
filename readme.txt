make all                            - assemble a project


./rsa_crypt                         - Сreate default keys for 2048 bit
./rsa_crypt -e message              - encrypt message
./rsa_crypt -d crypto-message       - decrypt message
./rsa_crypt -i                      - info
./rsa_crypt -h                      - help

./rsa_crypt -s size_key                                       - If you want to specify your key size
./rsa_crypt -n name_file_public_key name_file_private_key     - If you want to specify your own file names when creating keys
./rsa_crypt -i            - public key information
./rsa_crypt -h            - help


Exemples:
    ./rsa_crypt -s 512 -n my_pub.pem my_priv.pem
    ./rsa_crypt -e hello_world -n my_pub.pem
    ./rsa_crypt -d 20CE458CE323F9387494C96D1B5711CD2A313A.. -n my_priv.pem

Default (2048bit):
    ./rsa_crypt
    ./rsa_crypt -e "hello  world"
    ./rsa_crypt -d 11E63C2202E572671446FEF08C270BEBDB2861F..

Info about public key:
    ./rsa_crypt -i
        - Public-Key: (2048 bit)
        - Modulus HEX: D54212E86BDC9A642A4A527EA267..
        - Modulus DEC: 269213411919841670691106985814..
        - Exponent: 65537 (0x010001)

