from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework.views import APIView
from users.models import User, Department
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from notifications.models import Notification
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken



# from django.contrib.auth.models import User
class DepartmentSerializer(serializers.ModelSerializer):
    user_count = serializers.SerializerMethodField()

    class Meta:
        model = Department
        fields = ['id', 'name', 'user_count']  # Include other fields as necessary

    def get_user_count(self, obj):
        return obj.users.count() 

#user authentication
class UserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = User 
        fields = ['id', 'username', 'password', 'email',"department","branch","phone_number","role","is_active"]
    
class UserCreateSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = User 
        fields = ['id', 'username', 'password', 'email',"department","branch","phone_number","role","first_name","last_name"]
        
    def create(self, validated_data):
        # Get the password from validated data and hash it
        password = validated_data.pop('password', None)
        user = User(**validated_data)
        if password:
            user.set_password(password)  # Hash the password before saving
        user.save()
        return user
class CreateTicketUserSerializer(serializers.ModelSerializer):
    class Meta(object):
        model=User
        fields=['id','username','branch']   
class UserGetSerializer(serializers.ModelSerializer):
    class Meta(object):
        model = User 
        fields = '__all__'


#ticket app
from rest_framework import serializers
from tickets.models import Ticket, TicketCategory, TicketComment, TicketHistory, Attachment, Acknowledgement
  # Assuming you have a UserSerializer

class TicketCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = TicketCategory
        fields = ['id', 'name', 'description', 'image']
class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ['file', 'uploaded_at',]



class TicketCommentSerializer(serializers.ModelSerializer):
   
    created_at = serializers.DateTimeField(format='%Y-%m-%d %I:%M %p',read_only=True)

    class Meta:
        model = TicketComment
        fields = ['id', 'ticket', 'author', 'content', 'created_at', 'parent']
    def validate(self, data):
        if not data.get('content'):
            raise serializers.ValidationError('Solution content cannot be empty.')
        return data

class TicketHistorySerializer(serializers.ModelSerializer):
    updated_by = CreateTicketUserSerializer()
    updated_at = serializers.DateTimeField(format='%Y-%m-%d %I:%M %p',read_only=True)
    class Meta:
        model = TicketHistory
        fields = ['id', 'ticket', 'updated_at', 'updated_by', 'field_name', 'old_value', 'new_value']

class TicketAttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ['id', 'file', 'uploaded_at', 'ticket']

class TicketSerializer(serializers.ModelSerializer):
    attachments=TicketAttachmentSerializer(many=True,read_only=True)
    created_by = CreateTicketUserSerializer(read_only=True)
    assigned_to = UserSerializer(read_only=True)
    category = serializers.PrimaryKeyRelatedField(queryset=TicketCategory.objects.all())
    created_at = serializers.DateTimeField(format='%Y-%m-%d %I:%M %p',read_only=True)



    class Meta:
        model = Ticket
        fields = ['id', 'title', 'description', 'status', 'created_at', 'updated_at', 'category', 'assigned_to', 'created_by','attachments','priority']

class RecentTicketSerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField()
    department = serializers.StringRelatedField(source='department.name')
    category = serializers.StringRelatedField(source='category.name')

    class Meta:
        model = Ticket
        fields = ['created_by', 'category', 'department', 'created_at']

    def get_created_by(self, obj):
        user = obj.created_by
        return {
            'username': user.username,
            'department': user.department.name if user.department else None,
            'branch': user.branch  if user.branch else None,
        }
   
User = get_user_model()

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        try:
            user = User.objects.get(email=email)
            if not user.check_password(password):
                raise serializers.ValidationError("Invalid credentials")
        except User.DoesNotExist:
            raise serializers.ValidationError("user does not exist")
        token = self.get_token(user)
        return {
            'access': str(token.access_token),  
            'refresh': str(token), 
            'user': JWTUserSerializer(user).data,  
        }

class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    """Custom serializer to return both access and refresh tokens during refresh."""
    
    def validate(self, attrs):
        # Get the refresh token from the request
        refresh = attrs.get('refresh')
        
        try:
            # Decode the refresh token to get the user information
            refresh_token = RefreshToken(refresh)
            
            # Extract the user_id from the refresh token payload
            user_id = refresh_token['user_id']  # Or 'user' depending on how your payload is structured
            
            # Retrieve the user object using the user_id
            User = get_user_model()  # This should be called once at the start
            user = User.objects.get(id=user_id)
            
            # Generate a new access token
            new_token = refresh_token.access_token
            
            return {
                'access': str(new_token),  # Access token
                'refresh': str(refresh_token),  # Refresh token
                'user': JWTUserSerializer(user).data,  # User data (if needed)
            }
        
        except User.DoesNotExist:
            raise serializers.ValidationError("User matching query does not exist.")
        except Exception as e:
            raise serializers.ValidationError(f"Error refreshing token: {str(e)}")
class JWTUserSerializer(serializers.ModelSerializer):
    department = DepartmentSerializer()  # Nested serializer for department details

    class Meta:
        model = User
        fields = ['id','username', 'email', 'department', 'role','is_active']
class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'user', 'message', 'read', 'created_at', 'notification_type']
class MyTicketSerializer(serializers.ModelSerializer):
    attachments=TicketAttachmentSerializer(many=True,read_only=True)
    created_by = CreateTicketUserSerializer(read_only=True)
    assigned_to = UserSerializer(read_only=True)
    category = serializers.PrimaryKeyRelatedField(queryset=TicketCategory.objects.all())


    class Meta:
        model = Ticket
        fields = ['id', 'title', 'description', 'status', 'created_at', 'updated_at', 'category', 'assigned_to', 'created_by','attachments']

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    password = serializers.CharField(write_only=True)


class SendMailSerializer(serializers.Serializer):
    address = serializers.EmailField()
    subject = serializers.CharField(max_length=255)
    message = serializers.CharField()
    
    
class ReportTicketSerializer(serializers.ModelSerializer):
    attachments=TicketAttachmentSerializer(many=True,read_only=True)
    created_by = CreateTicketUserSerializer(read_only=True)
    assigned_to = UserSerializer(read_only=True)
    category = serializers.PrimaryKeyRelatedField(queryset=TicketCategory.objects.all())
    created_at = serializers.DateTimeField(format='%Y-%m-%d %I:%M %p',read_only=True)
    history = TicketHistorySerializer(many=True, read_only=True)  # Change here to allow multiple history records
    solution = TicketCommentSerializer(many=True, read_only=True) 


    class Meta:
        model = Ticket
        fields = ['id', 'title', 'description', 'status', 'created_at', 'updated_at', 'category', 'assigned_to', 'created_by','history','solution','attachments']

class AcknowledgementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Acknowledgement
        fields = '__all__'
        read_only_fields = ['author']