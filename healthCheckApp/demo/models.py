from django.db import models
from django.utils import timezone

class Department(models.Model):
    department_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Team(models.Model):
    team_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class User(models.Model):
    user_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=50)
    team = models.ForeignKey(Team, on_delete=models.SET_NULL, null=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username

class Session(models.Model):
    session_id = models.AutoField(primary_key=True)
    date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.date)
    
    def is_expired(self):
        return timezone.now() > self.date

class HealthCard(models.Model):
    card_id = models.AutoField(primary_key=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class Vote(models.Model):
    vote_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    team = models.ForeignKey(Team, on_delete=models.CASCADE)
    card = models.ForeignKey(HealthCard, on_delete=models.CASCADE)
    vote_value = models.IntegerField()
    progress_note = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Vote {self.vote_id} by {self.user}"

# class ProgressSummary(models.Model):
#     summary_id = models.AutoField(primary_key=True)
#     team = models.ForeignKey(Team, on_delete=models.CASCADE)
#     session = models.ForeignKey(Session, on_delete=models.CASCADE)
#     card = models.ForeignKey(HealthCard, on_delete=models.CASCADE)
#     overall_vote = models.TextField()
#     progress_trend = models.BooleanField()
#     created_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"Summary {self.summary_id}"
    

class ProgressSummary(models.Model):
    summary_id = models.AutoField(primary_key=True)
    team = models.ForeignKey(Team, null=True,blank=True,on_delete=models.CASCADE)
    session = models.ForeignKey(Session, on_delete=models.CASCADE)
    card = models.ForeignKey(HealthCard, on_delete=models.CASCADE)
    overall_vote = models.CharField(max_length=20)
    progress_trend = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('team', 'session', 'card')
        ordering = ['-created_at']

    def __str__(self):
        team_name = self.team.name if self.team else "No Team"
        card_title = self.card.title if self.card else "No Card"
        session_date = self.session.date.date() if self.session and self.session.date else "No Date"
        return f"{team_name} | {card_title} | {session_date} | {self.overall_vote}"
