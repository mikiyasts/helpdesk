from django.db import models
from django.contrib.auth.models import AbstractUser

class Department(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        app_label = 'users'

class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    branch = models.CharField(max_length=100, null=True, blank=True)  # Added max_length for branch
    department = models.ForeignKey(
        Department,
        null=True,
        blank=True,
        related_name='users',  # Ensure this related_name is unique and does not conflict
        on_delete=models.SET_NULL
    )
    role = models.CharField(
        max_length=20,
        choices=[
            ('employee', 'Employee'),
            ('it_officer', 'IT Officer'),
            ('admin', 'Admin')
        ],
        default='employee'
    )
    
    USERNAME_FIELD = 'email'  # Set email as the primary field for authentication
    REQUIRED_FIELDS = ['username']  
    
    def __str__(self):
        return self.email
class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.TextField()
    
class ActivateAccount(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    activated = models.BooleanField(default=False)