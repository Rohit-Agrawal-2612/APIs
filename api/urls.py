from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register),
    path('login/', views.login),
    path('registeration/', views.registeration),
    path('reg/', views.reg),
    path('verifypin/', views.verifypin),
    path('securityquestion/',views.securityquestion),
    path('password/', views.password),
]