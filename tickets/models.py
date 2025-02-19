from django.db import models
from users.models import User
class TicketCategory(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(null=True, blank=True)
    image = models.ImageField(upload_to='ticket_image/', null=True, blank=True)

    def __str__(self):
        return self.name

class Ticket(models.Model):
    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Closed', 'Closed'),
        ('Pending', 'Pending'),
    ]
    PRIORITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
       
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Open')
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='Low')
    created_at = models.DateTimeField(auto_now_add=True)
    category = models.ForeignKey(TicketCategory, related_name='tickets', on_delete=models.CASCADE)
    updated_at = models.DateTimeField(auto_now=True)
    assigned_to = models.ForeignKey(User, related_name='assigned_tickets', null=True, blank=True, on_delete=models.SET_NULL)
    created_by = models.ForeignKey(User, related_name='created_tickets', on_delete=models.CASCADE)
    
   

    def __str__(self):
        return self.title



class TicketComment(models.Model):
    ticket = models.ForeignKey(Ticket, related_name='comments', on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE)


class TicketHistory(models.Model):
    ticket = models.ForeignKey(Ticket, related_name='history', on_delete=models.CASCADE)
    updated_at = models.DateTimeField(auto_now_add=True)
    updated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    field_name = models.CharField(max_length=50)
    old_value = models.TextField(null=True, blank=True)
    new_value = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Ticket {self.ticket} updated by {self.updated_by} at {self.updated_at}"
    
class Attachment(models.Model):
    file = models.FileField(upload_to='attachments/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    ticket = models.ForeignKey(Ticket, null=True, blank=True, related_name='attachments', on_delete=models.CASCADE)

class Acknowledgement(models.Model):
    ticket = models.ForeignKey(Ticket, related_name='acknowledgement', on_delete=models.CASCADE)
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    