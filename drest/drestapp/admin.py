from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, EmailVerificationToken

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('id', 'username', 'email', 'is_active', 'email_verified')
    list_filter = ('is_staff', 'is_active', 'email_verified')
    #fieldsets = UserAdmin.fieldsets + (
        #(None, {'fields': ('email_verified',)}),
    #)
    #add_fieldsets = UserAdmin.add_fieldsets + (
        #(None, {'fields': ('email_verified',)}),
    #)

@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at', 'id', 'user_id_display')
    search_fields = ('user__email', 'token')

    def user_id_display(self, obj):
        return obj.user.id
    user_id_display.short_description = 'User ID' 








