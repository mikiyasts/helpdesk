from django.db import models

from users.models import User

class Notification(models.Model):
    user = models.ForeignKey(User, related_name='notifications', on_delete=models.CASCADE)
    message = models.TextField()
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    notification_type = models.CharField(max_length=20, choices=[
        ('Ticket', 'Ticket'),
        ('Chat', 'Chat'),
        ('System', 'System'),
    ], default='System')

    def __str__(self):
        return f"Notification for {self.user} - {self.notification_type}"