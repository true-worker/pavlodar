from django.contrib.auth.hashers import Argon2PasswordHasher
class PasswordHasher(Argon2PasswordHasher):
    time_cost = 3
    memory_cost = 65536
    parallelism = 2
