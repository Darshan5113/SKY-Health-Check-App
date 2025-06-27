from django import forms
from .models import User

class UserUpdateForm(forms.ModelForm):
    # clear_avatar = forms.BooleanField(required=False, label='Clear Avatar')

    class Meta:
        model = User
        fields = ['name', 'username', 'email', 'role', 'team', 'department']
    
    # def save(self, commit=True):
    #     user = super().save(commit=False)

    #     # If 'clear_avatar' is checked, remove the avatar
    #     if self.cleaned_data.get('clear_avatar'):
    #         user.avatar = None

    #     if commit:
    #         user.save()

    #     return user
