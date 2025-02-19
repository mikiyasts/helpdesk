from django.contrib import admin

from .models import Ticket,TicketCategory, TicketComment, TicketHistory, Attachment,Acknowledgement

admin.site.register(Ticket)
admin.site.register(TicketCategory)
admin.site.register(TicketComment)
admin.site.register(TicketHistory)
admin.site.register(Attachment)
admin.site.register(Acknowledgement)