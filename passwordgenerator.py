import json
import math
import secrets
import string

def calculate_entropy(length, pool_size):
    if pool_size == 0 or length == 0:
        return 0
    return length * math.log2(pool_size)

def evaluate_strength(entropy):
    if entropy < 50: return "WEAK"
    if entropy < 80: return "MODERATE"
    return "STRONG"

def generate_secure_password(length, use_digits, use_special):
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits if use_digits else ""
    special = string.punctuation if use_special else ""
    pool = lower + upper + digits + special
    if not pool: return "", 0
    password = [
        secrets.choice(lower),
        secrets.choice(upper)
    ]
    if use_digits: password.append(secrets.choice(digits))
    if use_special: password.append(secrets.choice(special))
    while len(password) < length:
        password.append(secrets.choice(pool))
    secrets.SystemRandom().shuffle(password)
    final_password = "".join(password)
    entropy = calculate_entropy(length, len(pool))
    return final_password, entropy

def main():
    print("=== ENTERPRISE KEY GENERATION TOOL ===")
    try:
        length = int(input("Length (Min 8, Max 2048): ").strip())
        if length < 8:
            print("Security Violation: Minimum length must be 8.")
            return
        if length > 2048:
            print("Resource Protection Fault: Maximum supported length is 2048 characters.")
            return
        digits = input("Include Digits? (y/n): ").lower().strip() == 'y'
        special = input("Include Special Chars? (y/n): ").lower().strip() == 'y'
        password, entropy = generate_secure_password(length, digits, special)
        strength = evaluate_strength(entropy)
        print("\n--- GENERATION REPORT ---")
        print(f"Key:      {password}")
        print(f"Entropy:  {entropy:.2f} bits")
        print(f"Status:   {strength}")
        export = input("\nExport metadata to local secure ledger? (y/n): ").lower().strip()
        if export == 'y':
            log_data = {"entropy_bits": round(entropy, 2), "classification": strength}
            with open("vault_manifest.json", "w") as f:
                json.dump(log_data, f, indent=2)
            print("Metadata saved to vault_manifest.json (Password excluded for zero-knowledge safety).")
    except ValueError:
        print("Execution Failure: Invalid numerical entry.")

if __name__ == "__main__":
    main()