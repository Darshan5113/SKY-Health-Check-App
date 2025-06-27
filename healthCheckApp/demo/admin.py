from django.contrib import admin
from .models import Department, Team, User, Session, HealthCard, Vote, ProgressSummary

admin.site.register(Department)
admin.site.register(Team)
admin.site.register(User)
admin.site.register(Session)
admin.site.register(HealthCard)
admin.site.register(Vote)
admin.site.register(ProgressSummary)