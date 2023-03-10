from django.urls import path
from .views import *
from app import views

urlpatterns = [
    path('admin', UserAPIView.as_view()), # post, get
    path('admins', UserAPIViews.as_view()), # Search and pagination
    path('admin/<int:pk>', UserAPIView.as_view()), # get by id
    path('login', login_view, name='login'), # login
    path('admin/update/<int:pk>', RetrieveUpdateDestroyAPIView.as_view()), # put, delete

    path('passwords', UpdatePassword.as_view()), # admin change password
    path('password', UpdatePasswords.as_view()), # recruiter change password

    path('reset', changepassword),
    path('confirm', reset_request),

    path('recruiter', RecruiterAPIView.as_view()), # post, get
    path('recruiters', RecruiterAPIViews.as_view()), # Search and pagination
    path('recruiter/<int:pk>', RecruiterAPIView.as_view()), #get by id
    path('recruiter/update/<int:pk>', RetrieveUpdateDestroyAPIViews.as_view()), # put, delete

    path('assessment', AssessmentAPIView.as_view()), #post, get
    path('assessment/<int:id>', AssessmentAPIView.as_view()), #get, put and delete
    path('assessments', AssessmentAPIViews.as_view()), #Search and Pagination
    
    path('plan', PlanAPIView.as_view()), #post
    path('plan/<int:id>', PlanAPIView.as_view()), #get, put and delete
    
    path('file', FileUploadView.as_view(), name='file-upload'), # post, get
    path('files/<int:id>', FileAPIView.as_view(), name='file'), # get by id
    # path('media/<str:filename>', FileAPIView.as_view(), name='file'), # get by id
    
    path('file/<int:id>', FileRetrieveUpdateDestroyAPIViews.as_view()), # put, delete
    path('files', FileUploadAPIViews.as_view()),
    
    path('media', display_images, name= 'img'),
    
    path("showing/<int:id>", views.ImageFetch,name="show"),
    
    path('view-pdf/<str:filename>', views.pdf_view,name='pdf_view'),
    
    # path('download/<str:filename>', views.stream_http_download),
    path('downloadpdf/<str:filename>', views.download_pdf_file, name='download_pdf_file'),
    
    path('data',RecAPIView.as_view())
]

# from urllib.request import urlopen 
# import base64

# base64.b64encode(urlopen("http://192.168.18.87/api/files/<int:id>").read())
