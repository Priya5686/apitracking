import requests

token = "ya29.a0AZYkNZivaSvo3dWv_1zDhbZxnY14hbRYWhx3bqccRqGNBP4RuVAVmnoeZMFwpMeRL2SovXqNJtYilH4gnjcXWLndBMYBL1Z-6UIS_mg3gc2wsDSEUkBbsycikkoPmNXGZISgGniZlfgdY9w-0WUnYGNPjro8_2AEybsMToyfaCgYKAasSARcSFQHGX2Mi7qQQ_PGIQ9XgdZngyfGjRg0175"
headers = {"Authorization": f"Bearer {token}"}
res = requests.get(
    "https://gmail.googleapis.com/gmail/v1/users/me/messages",
    headers=headers,
    params={"maxResults": 5}
)
print(res.status_code)
print(res.json())
