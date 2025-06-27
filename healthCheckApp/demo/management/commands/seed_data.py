from django.core.management.base import BaseCommand
from demo.models import Department, Team, User
import random

class Command(BaseCommand):
    help = 'Seed 3 departments, 6 teams, and 15 users'

    def handle(self, *args, **kwargs):
        # Clear existing data (optional, but useful for development)
        User.objects.all().delete()
        Team.objects.all().delete()
        Department.objects.all().delete()

        # Create departments
        departments = []
        dep_names = ['Engineering', 'Product', 'Design']
        for name in dep_names:
            dep = Department.objects.create(name=name)
            departments.append(dep)

        # Create teams (2 per department)
        teams = []
        for dep in departments:
            for i in range(1, 3):
                team = Team.objects.create(name=f"{dep.name} Team {i}", department=dep)
                teams.append(team)

        # Create users
        roles = ['Engineer', 'Team Leader', 'Department Leader']
        for i in range(1, 16):
            team = random.choice(teams)
            department = team.department
            role = random.choice(roles)
            User.objects.create(
                name=f"User {i}",
                username=f"user{i}",
                email=f"user{i}@example.com",
                password=f"pass{i}123",
                role=role,
                team=team,
                department=department
            )

        self.stdout.write(self.style.SUCCESS('✔ Successfully seeded 15 users, 6 teams, and 3 departments!'))
