from django.contrib import admin

from .models import Department, User,PasswordReset

admin.site.register(Department)
admin.site.register(User)
admin.site.register(PasswordReset)