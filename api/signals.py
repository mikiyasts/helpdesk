from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from tickets.models import Ticket
from notifications.models import Notification
from users.models import User

@receiver(post_save, sender=Ticket)
def create_notification_on_ticket_creation(sender, instance, created, **kwargs):
    if created:
        # Notify the user who created the ticket
        Notification.objects.create(
            user=instance.created_by,
            message=f"Your ticket '{instance.title}' has been created.",
            notification_type='Ticket'
        )
        
        # Notify users based on their roles
        # it_officer=User.objects.filter(role='it_officer')
        # for it_officers in it_officer:
        #     Notification.objects.create(
        #         user=it_officers,
        #         message=f"A new ticket '{instance.title}' has been assigned to you.",
        #         notification_type='Ticket'
        #     )
        
        # Notify all admins
        users=instance.created_by
        admins = User.objects.filter(role='admin')
        for admin in admins:
            Notification.objects.create(
                user=admin,
                message=f"A new ticket '{instance.title}' has been created by {instance.created_by.username}.",
                notification_type='Ticket'
            )
            
# @receiver(post_save, sender=Ticket)
# def notify_ticket_assigned(sender, instance, created, **kwargs):
#     # Only proceed if the ticket is updated (not created)
#     if not created:
#         # Check if the ticket is assigned for the first time and status is "In Progress"
#         if instance.assigned_to and instance.status == "In Progress" and instance.assigned_to != instance.created_by:
#             # Check if a notification has already been created for this ticket
#             existing_notifications = Notification.objects.filter(
#                 user=instance.created_by,
#                 message__icontains=instance.title
#             )

#             # If no notification exists, create one
#             if not existing_notifications.exists():
#                 Notification.objects.create(
#                     user=instance.created_by,
#                     message=f"Your ticket '{instance.title}' has been accepted by {instance.assigned_to.get_full_name()}.",
#                     notification_type='Ticket'
#                 )