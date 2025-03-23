import random

def generate_israeli_phone_numbers():
    phone_numbers= []
    for _ in range(100):
        prefix = random.choice(["050", "052", "053", "054", "055", "058"])
        number = prefix + "".join(random.choices("0123456789", k=7))
        phone_numbers.append(number)
    return phone_numbers


def choose_random_phone_number():
    israeli_phone_numbers = generate_israeli_phone_numbers()
    return random.choice(israeli_phone_numbers)





