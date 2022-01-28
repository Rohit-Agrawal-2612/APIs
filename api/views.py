import email,random,string
from multiprocessing import AuthenticationError
from django.conf import settings
from django.shortcuts import render
from matplotlib.style import use
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from api.models import MyUser
from .serializers import RegistrationSerializer
from django.http import JsonResponse
from rest_framework import status
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from django.core.mail import send_mail

from api import serializers

# Create your views here.

@api_view(['POST'])
def register(request):
    serializer = RegistrationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        user = MyUser.objects.get(email=serializer.data['email'])
        refresh = RefreshToken.for_user(user)
        content = {"msg":"user register successfully!!","result":"1","data":'',"payload":serializer.data,'refresh': str(refresh),'access': str(refresh.access_token)}
        return JsonResponse(content,status=status.HTTP_201_CREATED)
    else:
        content = {"msg":serializer.errors,"result":"0","data":""}
        return JsonResponse(content,status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def login(request):
    email = request.data['email']
    password = request.data['password']
    user = MyUser.objects.filter(email=email).first()
    if user is None:
        raise AuthenticationFailed("user not found!!")
    if not user.check_password(password):
        raise AuthenticationFailed("incorrect password!!")
    return JsonResponse({"message":"success"})    
    

@api_view(['POST'])
def registeration(request):
    password = request.data['password']
    email = request.data['email']
    user = authenticate(username=email, password=password)
    if user is not None:
        print("user id", user.id)
        sample_string = "qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPLKJHGFDSAZXVCBNM1234567890!@#$%?&*"
        pin = ''.join((random.choice(sample_string))for x in range(8))
        user.pin = pin
        user.save()
        refresh = RefreshToken.for_user(user)
        content = {"message":"user register successfully!!","result":"1","data":'','refresh': str(refresh),'access': str(refresh.access_token)}
        return JsonResponse(content)
    else:
        return JsonResponse({"message":"please contact your administrator"})

@api_view(['POST'])
def reg(request):
    try:
        user = MyUser.objects.filter(email=request.data['email'])[0]
    except:
        return JsonResponse({"message":"please contact your administrator"})
    print("user : ",user)
    if user is not None:
        if user.first_name == request.data['first_name']:
            if user.last_name == request.data['last_name']:
                if user.phone == request.data['phone']:
                    sample_string = "qwertyuioplkjhgfdsazxcvbnmQWERTYUIOPLKJHGFDSAZXVCBNM1234567890!@#$%?&*"
                    pin = ''.join((random.choice(sample_string))for x in range(8))
                    user.pin = pin
                    password = "12345678"
                    user.password = make_password(password)
                    user.save()
                    msg = f"Hi, {user.first_name}\nWelcome to the team. Your OTP is {pin}"
                    send_mail(
                    'verification mail',
                    msg,
                    settings.EMAIL_HOST_USER,
                    [request.data['email']],
                    fail_silently=False,
                    )
                    refresh = RefreshToken.for_user(user)
                    content = {"message":"success","result":"1","data":'','refresh': str(refresh),'access': str(refresh.access_token)}
                    return JsonResponse(content)
    return JsonResponse({"message":"please contact your administrator"})

@api_view(['POSt'])
def verifypin(request):
    try:
        user = MyUser.objects.get(id=request.data['id'])
    except:
        return JsonResponse({"message":"wrong id"})
    if user.pin == request.data['pin']:
        content = {"message":"verification success"}
        return JsonResponse(content,status=status.HTTP_202_ACCEPTED)
    content = {"message":"wrong pin"}
    return JsonResponse(content,status=status.HTTP_403_FORBIDDEN)

@api_view(['POST'])
def securityquestion(request):
    try:
        user = MyUser.objects.get(id=request.data['id'])
    except:
        return JsonResponse({"message":"wrong id"})
    user.security_question = request.data['security_question']
    user.security_answer = request.data['security_answer']
    user.save()
    content = {"message":"security added successfully!!"}
    return JsonResponse(content,status=status.HTTP_201_CREATED)

@api_view(['POST'])
def password(request):
    try:
        user = MyUser.objects.get(id=request.data['id'])
    except:
        return JsonResponse({"message":"wrong id"})
    old = user.password
    # user.password = make_password(request.data['password'])
    user.set_password(request.data['password'])
    user.save()
    new = user.password
    content = {"message":"password created successfully!!","old password":old,"new password":new}
    return JsonResponse(content,status=status.HTTP_201_CREATED)


