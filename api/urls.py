
from django.urls import path,include
from . import views
from rest_framework_simplejwt.views import (
   
    TokenRefreshView,
)
from .views import CustomTokenObtainPairView, DownloadAttachmentView, SubmitSolutionView, TicketReportView

urlpatterns = [
  path('',views.api_endpoints),
  path('signup/', views.signup),
  path('login/', views.login),
  path('getuser/', views.GetUserView.as_view()),
  path('logout/',views.logout),
  path('generate-apikey/',views.GenerateAPIKeyView.as_view()),
  path('SendSMS/',views.send_message_view),
 path('password_reset/', views.password_reset, name='password_reset_request'),
 path('change_password/<uidb64>/<token>/', views.change_password, name='reset_password'),

   
  path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
  path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
  
  
  
  
  path('list_ticket/', views.list_tickets),
  path('create_ticket/', views.create_ticket),
  path('list_ticket/<int:pk>/',views.ticket),
  path('edit_ticket/<int:pk>/',views.edit_ticket),
  path('acknowledgement/<int:ticket_id>/',views.acknowledgement),
  path('create_acknowledgement/',views.create_acknowledgement),
  path('list_acknowledgements/',views.list_acknowledgements),
  path('reverse_ticket/<int:ticket_id>/',views.reverse_ticket),
  
  
  
  
  
  path('list_ticket_category/', views.list_ticket_category),
  path('create_ticket_category/', views.create_ticket_category),
  path('list_ticket_category_detail/<int:pk>/', views.list_ticket_category_detail),
  path('delete_ticket_category/<int:pk>/', views.delete_ticket_category),
  path('my_ticket/', views.my_ticket),
  path('submit_solution/<int:ticket_id>/', SubmitSolutionView.as_view() ),
  path('update_ticket_history/<int:id>/',views.ticket_status_history),
  path('list_ticket_history/<int:id>/',views.solutions),
  path('accept_ticket/<int:id>/',views.acceptticket),
  path('check_pending_tickets/',views.check_pending_tickets),
  path('close_ticket/<int:id>/',views.close_ticket),
  path('list_solution/<int:id>/',views.list_solution),
  path('download_attachment/<int:id>',views.DownloadAttachmentView),
  
  
  
  path('admin-dashboard/', views.admin_dashboard),
  path('systemusers/', views.get_all_users),
  path('edituser/<str:pk>/', views.edit_user),
  path('create_user/',views.create_user),
  path('create_user_signup/',views.create_user_signup),
  path('check_activation_status/<str:user_id>/',views.check_activation_status),
  path('activate_account/<str:encrypted_user_id>/',views.activate_account),
  
  path('departments/',views.departments),
  path('create_department/',views.create_department),
  path('edit_department/<int:pk>/', views.edit_department),
  
  path('notifications/', views.ListNotificationsView.as_view()),
  path('notifications/<int:pk>/mark-as-read/', views.MarkNotificationAsReadView.as_view()),
  path('mark_all_as_read/',views.MarkAllNotificationAsRead.as_view()),




  path('report/tickets/', views.TicketReportView, name='ticket-report'),
] 