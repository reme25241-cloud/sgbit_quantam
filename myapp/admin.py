# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *
from django.contrib.auth.models import Group

# Remove default Groups from admin
admin.site.unregister(Group)

# Customize admin interface branding
admin.site.site_header = "Messaging"
admin.site.site_title = "Messaging Admin"
admin.site.index_title = "Dashboard" 

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'name', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_active', 'gender')
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('name', 'contact', 'age', 'gender')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'groups', 'user_permissions')}),
        ('Dates', {'fields': ('last_login', 'date_joined')}),
    )
    search_fields = ('email', 'name')
    ordering = ('email',)


from django.contrib import admin
from .models import Feedback

@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ['user', 'created_at', 'resolved']
    list_filter = ['resolved']
    search_fields = ['user__name', 'message']

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('id', 'sender', 'receiver', 'timestamp', 'is_group_message')
    search_fields = ('sender__email', 'receiver__email', 'text')
    list_filter = ('is_group_message', 'timestamp')
    readonly_fields = ('timestamp',)
    

