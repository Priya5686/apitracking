from django.contrib.auth import get_user_model
from social_core.exceptions import AuthException
from social_core.exceptions import AuthAlreadyAssociated

User = get_user_model()

def link_to_existing_user(backend, details, user=None, *args, **kwargs):
    """If not logged in, try to link Google to existing user with same email."""
    if user:
        return {'user': user}

    email = details.get('email')
    if not email:
        return

    try:
        existing_user = User.objects.get(email=email)
        # Raise if this user already linked to a different social account
        if backend.strategy.storage.user.get_social_auth(backend.name, kwargs['uid']):
            raise AuthAlreadyAssociated(backend, "That social account is already in use.")

        return {'user': existing_user}
    except User.DoesNotExist:
        return


"""def social_uid(backend, details, response, *args, **kwargs):
    print(f"Social UID Response: {response}")
    uid = response.get('id')  # Example for Google OAuth
    if not uid:
        raise Exception("Failed to fetch UID from the social provider.")
    return {'uid': uid}


from social_core.exceptions import AuthException

def associate_user_override(backend, user=None, *args, **kwargs):
    from social_django.models import UserSocialAuth

    if user:
        try:
            # Check and create the UserSocialAuth record
            if not UserSocialAuth.objects.filter(user=user, provider=backend.name).exists():
                UserSocialAuth.objects.create(
                    user=user,
                    provider=backend.name,
                    uid=kwargs.get('uid')
                )
                print(f"Successfully associated user {user} with provider {backend.name}.")
            else:
                print(f"User {user} is already associated with provider {backend.name}.")
        except AuthException as e:
            print(f"Error during association: {str(e)}")
    else:
        print("No user found to associate.")



from social_core.exceptions import AuthException

def associate_existing_account(backend, user=None, response=None, *args, **kwargs):
    email = response.get('email')
    if email:
        User = get_user_model()
        # Check if the social account is already linked to another user
        existing_user = User.objects.filter(email=email).first()
        if existing_user and user and existing_user != user:
            raise AuthException(backend, f"This social account is already linked to another user: {existing_user}.")
        elif existing_user:
            print(f"User {email} is already associated with {backend.name}.")"""


def debug_pipeline_step(backend, user=None, *args, **kwargs):
    print(f"Backend: {backend.name}")
    print(f"User: {user}")
    print(f"Args: {args}")
    print(f"Kwargs: {kwargs}")
