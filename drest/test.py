from pywebpush import generate_vapid_keys

vapid_keys = generate_vapid_keys()

print("🔑 Public VAPID Key:", vapid_keys["publicKey"])
print("🔒 Private VAPID Key:", vapid_keys["privateKey"])
