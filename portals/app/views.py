import json
import mimetypes
import os
from django.forms import DateTimeField
from django.shortcuts import render, redirect

from rest_framework.decorators import api_view
# Create your views here.
from .models import *
from .serializers import *
from django.http.response import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.generics import ListCreateAPIView
from rest_framework import filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status
from django.http import HttpResponse, Http404, StreamingHttpResponse, FileResponse
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework import exceptions
from app.utils import generate_access_token, generate_refresh_token
from rest_framework.generics import (ListCreateAPIView, RetrieveUpdateDestroyAPIView)
from django.core.mail import send_mail  
from rest_framework import viewsets
from rest_framework import status
from rest_framework import generics

@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def login_view(request):

    Email = request.data.get('Email')
    Password = request.data.get('Password')
    response = Response()
    if (Email is None) or (Password is None):
        raise exceptions.AuthenticationFailed(
            'email and password required')

    user = User.objects.filter(Email=Email).first()
    user = User.objects.filter(Password=Password).first()
    admin = Recruiters.objects.filter(Email=Email).first()
    admin = Recruiters.objects.filter(Password=Password).first()
    if User.objects.filter(Email=Email).exists():
        if(user is None):
          raise exceptions.AuthenticationFailed('user not found')
    # if (not user.check_password(Password)):
    #     raise exceptions.AuthenticationFailed('wrong password')

        serialized_user = UserSerializer(user).data

        access_token = generate_access_token(user)
        refresh_token = generate_refresh_token(user)

        response.set_cookie(key='refreshtoken', value=refresh_token, httponly=True)
        response.data = {
            'status': 'success',
            'access_token': access_token,
            'user': serialized_user,
        }

        return response

    if Recruiters.objects.filter(Email=Email).exists():
        if(admin is None):
         raise exceptions.AuthenticationFailed('user not found')

        serialized_user = RecruiterSerializer(admin).data

        access_token = generate_access_token(admin)
        refresh_token = generate_refresh_token(admin)

        response.set_cookie(key='refreshtoken', value=refresh_token, httponly=True)
        response.data = {
          'status': 'success',
          'access_token': access_token,
         'user': serialized_user,
        }

        return response


class UserAPIView(APIView):
    permission_classes = ([AllowAny])

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Http404

    def get(self, request, pk=None, format=None):
        if pk:
            data = self.get_object(pk)
            serializer = UserSerializer(data)
            return Response(serializer.data)
        else:
            data = User.objects.all().order_by('-id')
            serializer = UserSerializer(data, many=True)
            return Response(serializer.data)
                 
    def post(self, request, *args, **kwargs):
        user = UserSerializer(data=request.data)
        user.is_valid(raise_exception=True)
        user.save()

        UserName = user.data.get('UserName')
        Password = user.data.get('Password')
        email = request.data['Email']
        subject = 'Mail From Recruitment Portal'
        message = 'Your Credentials are: UserName = '+str(UserName) + '   Password = '+str(Password)
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        send_mail(subject, message=message, from_email=from_email, recipient_list=recipient_list)

        return Response({
            'message' : 'Admin created successfully',
            'data' : user.data
        })

class RetrieveUpdateDestroyAPIView(APIView):
    permission_classes = (IsAdminUser, IsAuthenticated)
    def put(self, request, pk=None, format=None):
        user = User.objects.get(pk=pk)
        serializer = UserSerializer(instance=user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'message' : 'Admin updated successfully',
            'data' : serializer.data
        })

    def delete(self, request, pk, format=None):
        user = User.objects.get(pk=pk)
        user.delete()
        return Response({
            'message' : 'Admin deleted successfully'
        })
        
class RecruiterAPIView(APIView):
    permission_classes = ([AllowAny])
    def get_object(self, pk):
        try:
            return Recruiters.objects.get(pk=pk)
        except Recruiters.DoesNotExist:
            return Http404
        
    def get(self, request, pk = None, format=None):
        if pk:
            data = self.get_object(pk)
            serializer = RecruiterSerializer(data)
            return Response(serializer.data)
        else:
            data = Recruiters.objects.all().order_by('-id')
            serializer = RecruiterSerializer(data, many=True)
            return Response(serializer.data)
        
    def post(self, request, *args, **kwargs):
        recruiter =RecruiterSerializer(data=request.data)
        recruiter.is_valid(raise_exception=True)
        recruiter.save()
        
        UserName = recruiter.data.get('UserName')
        Password = recruiter.data.get('Password')
        email = request.data['Email']
        subject = 'Mail From Recruitment Portal'
        message = 'Your Credentials are: UserName = '+str(UserName) + '   Password = '+str(Password)
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        send_mail(subject, message=message, from_email=from_email, recipient_list=recipient_list)

        return Response({
            'message' : 'Recruiter created successfully',
            'data' : recruiter.data,
        })
        
class RetrieveUpdateDestroyAPIViews(APIView):
    permission_classes = (AllowAny,)
    def put(self, request, pk=None,format=None):
        recruiter = Recruiters.objects.get(pk=pk)
        serializer = RecruiterSerializer(instance=recruiter, data=request.data,partial = True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'message' : 'Recruiter updated successfully',
            'data' : serializer.data
        })
        
    def delete(self, request, pk, format=None):
        recruiter = Recruiters.objects.get(pk=pk)
        recruiter.delete()
        return Response({
            'message' : 'Recruiter deleted successfully.'
        })

class UserAPIViews(ListCreateAPIView):
    serializer_class = UserSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['UserName']
    
    filterset_fields = ['id', 'UserName']
    search_fields = ['id', 'UserName']
    
    def get_queryset(self):
        return User.objects.filter().order_by('UserName')

class RecruiterAPIViews(ListCreateAPIView):
    serializer_class = RecruiterSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['UserName']
    
    filterset_fields = [ 'UserName']
    search_fields = [ 'UserName']
    
    def get_queryset(self):
        return Recruiters.objects.filter().order_by('UserName')

class FileUploadAPIViews(ListCreateAPIView):
    permission_classes = [AllowAny,]
    serializer_class = FileUploadDisplaySerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['location']
    
    filterset_fields = [ 'location']
    search_fields = ['location']
    
    def get_queryset(self):
        return FileUpload.objects.filter().order_by('location')

class UpdatePassword(APIView):
    """
    An endpoint for changing password.
    """
    permission_classes = (IsAuthenticated, )

    def get_object(self, queryset=None):
        return self.request.user

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            oldpassword = serializer.data.get("oldpassword")
            if not User.objects.filter(Password=oldpassword):
                return Response({"oldpassword": ["Wrong password."]}, 
                                status=status.HTTP_400_BAD_REQUEST)
            user = self.get_object()
            newpassword = serializer.data['newpassword']
            user.Password = newpassword
            user.save()
            # return Response(user)
            return Response({'message':'password changed successfully'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdatePasswords(APIView):
    """
    An endpoint for changing password.
    """
    permission_classes = (IsAuthenticated, IsAdminUser )

    def get_object(self, queryset=None):
        return self.request.user

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            oldpassword = serializer.data.get("oldpassword")
            if not Recruiters.objects.filter(Password=oldpassword):
                return Response({"oldpassword": ["Wrong password."]}, 
                                status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            user = self.get_object()
            newpassword = serializer.data['newpassword']
            user.Password = newpassword
            # self.object.set_password(serializer.data.get("newpassword"))
            user.save()
            # return Response(user)
            return Response({'message':'password changed successfully'}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





@api_view(['PUT'])
@permission_classes([AllowAny])
def changepassword(request):
    
    data = request.data
    Email = data['Email']
    # Otp = ''.join(random.choices( string.digits, k=4))
    user = User.objects.filter(Email=Email).first()
    recruiter = Recruiters.objects.filter(Email=Email).first()

    if user:
        serializer = UserSerializer(instance=user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        Otp = serializer.data['otp']
        if User.objects.filter(Email=Email).exists():
           subject = 'Mail From Recruitment Portal'
           message = 'Your otp is: ' + str(Otp)
           from_email = settings.EMAIL_HOST_USER
           recipient_list = [Email]

           send_mail(subject, message=message, from_email=from_email, recipient_list=recipient_list)

        message = {
                 'detail': 'Success Message',
                 'data': serializer.data}
        return Response(message, status=status.HTTP_200_OK)

    if recruiter:
        serializer = RecruiterSerializer(instance=recruiter, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        Otp = serializer.data['otp']
        if Recruiters.objects.filter(Email=Email).exists():
           subject = 'Mail From Recruitment Portal'
           message = 'Your otp is: ' + str(Otp)
           from_email = settings.EMAIL_HOST_USER
           recipient_list = [Email]

           send_mail(subject, message=message, from_email=from_email, recipient_list=recipient_list)

        message = {
                 'detail': 'Success Message',
                 'data': serializer.data}
        return Response(message, status=status.HTTP_200_OK)


    else:
        message = {
            'detail': 'Some Error Message'}
        return Response(message, status=status.HTTP_400_BAD_REQUEST)




@api_view(['PUT'])
@permission_classes([AllowAny])
def reset_request(request):
    
    serializer = resetpasswordSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    Email = serializer.data['Email']

    user = User.objects.filter(Email=Email).first()
    recruiter = Recruiters.objects.filter(Email=Email).first()

    if user:
        
        if User.objects.filter(Email=Email).exists():
            newpassword = serializer.data['newpassword']
            confirmpassword = serializer.data['confirmpassword']
            if (newpassword!=confirmpassword):
                return Response({'message':'password mismatch'})
            else:
                user.Password = newpassword
                user.save()
                return Response({
                    'message':'Password reset successfully'
                })

    if recruiter:
        if Recruiters.objects.filter(Email=Email).exists():
            newpassword = serializer.data['newpassword']
            confirmpassword = serializer.data['confirmpassword']
            if (newpassword!=confirmpassword):
                return Response({'message':'password mismatch'})
            else:
                recruiter.Password = newpassword
                recruiter.save()
                return Response({
                    'message':'Password reset successfully'
                })


@api_view(['PUT'])
def reset_password(request):
    """reset_password with email, OTP and new password"""
    data = request.data
    user = User.objects.get(email=data['email'])
    if user.is_active:
        # Check if otp is valid
        if data['otp'] == user.otp:
            if password != '':
                # Change Password
                user.set_password(data['password'])
                user.save() # Here user otp will also be changed on save automatically 
                return Response('any response or you can add useful information with response as well. ')
            else:
                message = {
                    'detail': 'Password cant be empty'}
                return Response(message, status=status.HTTP_400_BAD_REQUEST)
        else:
            message = {
                'detail': 'OTP did not matched'}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)
    else:
        message = {
            'detail': 'Something went wrong'}
        return Response(message, status=status.HTTP_400_BAD_REQUEST)

  
# class FileAPIView(APIView):
#     parser_classes = (MultiPartParser, FormParser)
#     permission_classes = [IsAuthenticated]
#     def get_object(self, pk):
#         try:
#             return FileUpload.objects.get(pk=pk)
#         except FileUpload.DoesNotExist:
#             return Http404
        
#     def get(self, request, pk = None, format=None):
#         if pk:
#             data = self.get_object(pk)
#             serializer = FileUploadDisplaySerializer(data)
#             return Response(serializer.data)
        # else:
        #     data = Files.objects.all()
        #     serializer = FileSerializer(data, many=True)
        #     return Response(serializer.data)
    
class FileRetrieveUpdateDestroyAPIViews(APIView):
    permission_classes = (AllowAny,)
    def put(self, request, id=None,format=None):
        file = FileUpload.objects.get(id=id)
        serializer = FileUploadDisplaySerializer(instance=file, data=request.data, partial = True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'message' : 'File updated successfully',
            'data' : serializer.data
        })
        
    def delete(self, request, id, format=None):
        file = FileUpload.objects.get(id=id)
        file.delete()
        return Response({
            'message' : 'File deleted successfully.'
        })


class FileUploadView(generics.ListCreateAPIView):
   
    permission_classes = [AllowAny,]
    serializer_class = FileUploadDisplaySerializer
    def post(self, request, format=None): 
        serializer = FileUploadSerializer(data=request.data)
        if serializer.is_valid():    #validate the serialized data to make sure its valid       
            qs = serializer.save()                     
            message = {'detail':qs, 'status':True}
            return Response(message, status=status.HTTP_201_CREATED)
            # return redirect("show")
        else: #if the serialzed data is not valid, return erro response
            data = {"detail":serializer.errors, 'status':False}            
            return Response(data, status=status.HTTP_400_BAD_REQUEST)
    def get_queryset(self):
        return FileUpload.objects.all().order_by('-id')
    
def ImageFetch(request, id = None):
    all_img = FileUpload.objects.get(id=id)
    return (request,{'key1':all_img})

class FileAPIView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [AllowAny,]
    def get_object(self, queryset=None):
        return self.request.user
        
    def get(self, request, id = None, format=None):
        self.object = self.get_object()
        
        data = FileUpload.objects.get(id=id)
        try:
            if id:
                serializer = FileUploadDisplaySerializer(data)
      
                return Response({'data':serializer.data,})
        except FileUpload.DoesNotExist:
            return Http404
        
from django.shortcuts import render,redirect

def display_images(request):
        
        if request.method == 'GET':
            
            file = FileUpload.objects.all()
            return (request,{'img': file , 'media_url':settings.MEDIA_URL})
    

# from django.middleware.csrf import get_token
# import base64
# import pyperclip


# def stream_http_download(request, filename):
#     try:
#         BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#         filepath = BASE_DIR + '/app/media/' + filename
#         response = StreamingHttpResponse(open(filepath, 'rb'))
#         # response['content_type'] = "application/octet-stream"
#         # response['Content-Disposition'] = 'attachment; filename=' + os.path.basename(filepath)
#         # return response
#         image_read = response.read()
#         image_64_encode = base64.b64encode(image_read)
#         return image_64_encode
#     except Exception:
#         raise Http404


def download_pdf_file(request, filename=""):
    if filename != "":
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filepath = BASE_DIR + '/media/' + filename
        path = open(filepath, 'rb')
        mime_type, _ =mimetypes.guess_type(filepath)
        response = HttpResponse(path, content_type=mime_type)
        response['content_type'] = "application/octet-stream"
        response['content-Disposition'] = "attachment; filename=%s" %filename
        return response
        
# def download_pdf_file(request, filepath=""):
#     if filepath !="":
#         BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#         filename = BASE_DIR + '/media/' + filepath
#         path = open(filename, 'rb')
#         mime_type, _ =mimetypes.guess_type(filename)
#         response = HttpResponse(path, content_type=mime_type)
#         response['content_type'] = "application/octet-stream"
#         response['content-Disposition'] = "attachment; filename=%s" %filepath
#         return response
        
class AssessmentAPIView(APIView):
    permission_classes = (AllowAny,)
    def get_object(self, id):
        try:
            return Assessment.objects.get(id=id)
        except Assessment.DoesNotExist:
            return Http404
        
    def get(self, request, id= None, format=None):
        if id:
            data = self.get_object(id)
            serializer = AssessmentSerializer(data)
            return Response(serializer.data)
        else:
            data = Assessment.objects.all()
            serializer = AssessmentSerializer(data, many=True)
            return Response(serializer.data)
        
    def post(self, request, *args, **kwargs):
        assessment = AssessmentSerializer(data=request.data)
        assessment.is_valid(raise_exception=True)
        assessment.save()
        
        return Response({
            'message' : 'Assessment created successfully',
            'data' : assessment.data
        })
        
    def put(self,request, id=None, format=None):
        assessment = Assessment.objects.get(id=id)
        serializer = AssessmentSerializer(instance=assessment, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'message' : 'Assessment updated successfully',
            'data' : serializer.data
        })
        
    def delete(self, request, id, format=None):
        assessment = Assessment.objects.get(id=id)
        assessment.delete()
        return Response({
            'message' : 'Assessment deleted successfully'
        })
            
class AssessmentAPIViews(ListCreateAPIView):
    serializer_class = AssessmentSerializer
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['Name']
    
    filterset_fields = ['id', 'Name', 'Tags']
    search_fields = ['id', 'Name', 'Tags']
    
    def get_queryset(self):
        return Assessment.objects.filter().order_by('Name')
    
    
class PlanAPIView(APIView):
    permission_classes = (AllowAny,)
    def get_object(self, id):
        try:
            return Plan.objects.get(id=id)
        except Plan.DoesNotExist:
            return Http404
        
    def get(self, request, id=None, format=None):
        if id:
            data = self.get_object(id)
            serializer = PlanSerializer(data)
            return Response(serializer.data)
        else:
            data = Plan.objects.all()
            serializer = PlanSerializer(data, many=True)
            return Response(serializer.data)
    
    def post(self, request,*args, **kwargs):
        plan = PlanSerializer(data=request.data)
        plan.is_valid(raise_exception=True)
        plan.save()
        
        return Response({
            
            'message' : 'Plan created successfully',
            'data' : plan.data
        }) 
        
    def put(self, request, id=None, formate=None):
        plan = Plan.objects.get(id=id)
        plan = PlanSerializer(instance=plan, data=request.data, partial=True)
        plan.is_valid(raise_exception=True)
        plan.save()
        
        return Response({
            'message' : 'Plan updated successfully',
            'data' : plan.data
        })
        
    def delete(self, request, id, format=None):
        plan = Plan.objects.get(id=id)
        plan.delete()
        return Response({
            'message' : 'Plan deleted successfully'
        })
        
        
def pdf_view(request, filename=''):
    if filename != '':
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        filepath = BASE_DIR + '/media/' + filename
        with open(filepath, 'rb') as pdf:
            response = HttpResponse(pdf.read(), content_type='application/pdf')
            response['Content-Disposition'] = 'inline;filename=mypdf.pdf'
            return response
        
        
# from datetime import date, timedelta
# from django.contrib.admin.filters import (
#     SimpleListFilter)

# class WeekFilter(Recruiters.SimpleListFilter):
#     title = _("Week")
#     parameter_name = "week"

#     def lookups(self, request, model_admin):
#         return (
#             ('1', 'This week'),
#         )

#     def queryset(self, request, queryset):
#         if self.value() == '1':
#             week_start = date.today()
#             week_start -= timedelta(days=week_start.weekday())
#             week_end = week_start + timedelta(days=7)
#             return queryset.filter(
#                 created_at__gte=week_start,
#                 created_at__lt=week_end
#             )
#         return queryset


from datetime import timedelta, datetime
from django.utils import timezone
class RecAPIView(APIView):
    permission_classes = [AllowAny,]
    def get(self,request,*args, **kwargs):
        some_day_last_week = timezone.now().date() - timedelta(days=7)
        monday_of_last_week = some_day_last_week - timedelta(days=(some_day_last_week.isocalendar()[2] - 1))
        monday_of_this_week = monday_of_last_week + timedelta(days=7)
        # created_at = {
        #     'monday_of_last_week' : monday_of_last_week,
        #     'monday_of_this_week' : monday_of_this_week,
        # }
        data = Recruiters.objects.filter()
        return Response(data)
    
from django.db.models.functions import Cast
from django.db.models.functions import ( TruncDate, TruncDay, TruncMonth, TruncWeek, TruncYear, )
from django.db.models import Avg
# import datetime
# class RecruitersAPIView(APIView):
#     def get(self,request,*args, **kwargs):
#         serializer_class = RecruiterSerializer
#     queryset = Recruiters.objects.all()
#     filter_fields = {'created_at': ['iexact', 'lte', 'gte']}
#     # http_method_names = ['get', 'post', 'head']

#     GROUP_CASTING_MAP = {  # Used for outputing the reset datetime when grouping
#         'day': Cast(TruncDate('created_at'), output_field=DateTimeField()),
#         'month': Cast(TruncMonth('created_at'), output_field=DateTimeField()),
#         'week': Cast(TruncWeek('created_at'), output_field=DateTimeField()),
#         'year': Cast(TruncYear('created_at'), output_field=DateTimeField()),
#     }

#     GROUP_ANNOTATIONS_MAP = {  # Defines the fields used for grouping
#         'day': {
#             'day': TruncDay('created_at'),
#             'month': TruncMonth('created_at'),
#             'year': TruncYear('created_at'),
#         },
#         'week': {
#             'week': TruncWeek('created_at')
#         },
#         'month': {
#             'month': TruncMonth('created_at'),
#             'year': TruncYear('created_at'),
#         },
#         'year': {
#             'year': TruncYear('created_at'),
#         },
#     }

#     def list(self, request, *args, **kwargs):
#         group_by_field = request.GET.get('group_by', None)
#         if group_by_field and group_by_field not in self.GROUP_CASTING_MAP.keys():  # validate possible values
#             return Response(status=status.HTTP_400_BAD_REQUEST)

#         queryset = self.filter_queryset(self.get_queryset())

#         if group_by_field:
#             queryset = queryset.annotate(**self.GROUP_ANNOTATIONS_MAP[group_by_field]) \
#                 .values(*self.GROUP_ANNOTATIONS_MAP[group_by_field]) \
#                 .annotate(rank=Avg('rank'), created_at=self.GROUP_CASTING_MAP[group_by_field]) \
#                 .values('rank', 'created_at')

#         page = self.paginate_queryset(queryset)
#         if page is not None:
#             serializer = self.get_serializer(page, many=True)
#             return self.get_paginated_response(serializer.data)

#         serializer = self.get_serializer(queryset, many=True)
#         return Response(serializer.data)
    