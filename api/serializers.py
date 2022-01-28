from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from api.models import MyUser

class RegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyUser
        fields = ('email','phone','first_name','last_name','password')
        extra_kwargs = {
            'password': {'write_only':True}
        }
    
    def create(self, validated_data):
        user = MyUser.objects.create(**validated_data)
        if user.password is not None:
            user.password = make_password(user.password)
        user.save()
        return user