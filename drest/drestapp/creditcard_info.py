import plaid
from plaid.api import plaid_api
from plaid.model.products import Products
from plaid.model.sandbox_public_token_create_request import SandboxPublicTokenCreateRequest
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.liabilities_get_request import LiabilitiesGetRequest

# Your Plaid credentials
PLAID_CLIENT_ID = "6845d7e27a4f700021ffb594"
PLAID_SECRET = "8ad79816afb586a6ed2e28092655fa"

# Configure Plaid API client
configuration = plaid.Configuration(
    host=plaid.Environment.Sandbox,
    api_key={
        'clientId': PLAID_CLIENT_ID,  
        'secret': PLAID_SECRET,
    }
)
print("Client ID:", PLAID_CLIENT_ID)
print("Secret:", PLAID_SECRET)

api_client = plaid.ApiClient(configuration)
client = plaid_api.PlaidApi(api_client)

def fetch_credit_card_info():
    """Fetches credit card liabilities from Plaid Sandbox."""
    try:
        # Step 1: Create sandbox public token for liabilities product
        request = SandboxPublicTokenCreateRequest(
            institution_id="ins_109508",
            initial_products=[Products("liabilities")]
        )
        response = client.sandbox_public_token_create(request)
        public_token = response.public_token

        # Step 2: Exchange public token for access token
        exchange_request = ItemPublicTokenExchangeRequest(public_token=public_token)
        exchange_response = client.item_public_token_exchange(exchange_request)
        access_token = exchange_response.access_token

        # Step 3: Retrieve credit card (liabilities) info
        liabilities_request = LiabilitiesGetRequest(access_token=access_token)
        liabilities_response = client.liabilities_get(liabilities_request)

        # Display credit card details
        credit_cards = liabilities_response.liabilities.credit
        for card in credit_cards:
            print("\n💳 Credit Card Info")
            print("Account ID:", card.account_id)
            print("Last Payment Amount:", card.last_payment_amount)
            print("Last Payment Date:", card.last_payment_date) 
            print("Minimum Payment Amount:", card.minimum_payment_amount)
            print("Next Payment Due Date:", card.next_payment_due_date)
            print("Last Statement Balance:", card.last_statement_balance)
            print("-" * 40)

    except Exception as e:
        print("❌ Error fetching credit card liabilities:", e)

# Run standalone function
if __name__ == "__main__":
    fetch_credit_card_info()
