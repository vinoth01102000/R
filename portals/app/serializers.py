from .models import *
from rest_framework import serializers
from django.conf import settings
from django.core.mail import send_mail

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'
        
class RecruiterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Recruiters
        fields = '__all__'
 
class AssessmentSerializer(serializers.ModelSerializer):
    class Meta :
        model = Assessment
        fields = '__all__'
        
class PlanSerializer(serializers.ModelSerializer):
    class Meta :
        model = Plan
        fields = '__all__'
 
class ChangePasswordSerializer(serializers.Serializer):
    oldpassword = serializers.CharField(required=True, max_length=30)
    newpassword = serializers.CharField(required=True, max_length=30)
    confirmpassword = serializers.CharField(required=True, max_length=30)

class resetpasswordSerializer(serializers.Serializer):
    Email = serializers.EmailField(required=True, max_length=50)
    otp = serializers.CharField(required=True, max_length=15)
    newpassword = serializers.CharField(required=True, max_length=30)
    confirmpassword = serializers.CharField(required=True, max_length=30)


class FileUploadSerializer(serializers.ModelSerializer):   
    # location = serializers.JSONField(default=dict)
    # experience = serializers.JSONField(default=dict)
    # company = serializers.JSONField(default=dict)
    # designation = serializers.JSONField(default=dict)      
    file = serializers.ListField(
        child=serializers.FileField(max_length=100000,
        allow_empty_file=False,
        use_url=False ))

    class Meta:
        model = FileUpload
        fields = ('id', 'location', 'experience', 'company', 'designation', 'file', 'thumbnail')

    def create(self, validated_data):
        location=validated_data['location']
        experience=validated_data['experience']
        company=validated_data['company']
        designation=validated_data['designation']
        file=validated_data.pop('file')   
        image_list = []     
        for img in file:
            photo=FileUpload.objects.create(file=img,location=location,experience=experience,company=company,designation=designation)
            imageurl = f'{photo.file.url}'
            image_list.append(imageurl)    
         
        return ({
            'location': location, 
            'experience': experience,
            'company': company,
            'designation': designation,
            'file': image_list,
            })


class FileUploadDisplaySerializer(serializers.ModelSerializer):        
    class Meta:
        model = FileUpload
        fields = ('id', 'location', 'experience', 'company', 'designation', 'file', 'thumbnail')

        

# from rest_framework import serializers
# from easy_thumbnails_rest.serializers import ThumbnailerSerializer

# class ExampleSerializer(serializers.ModelSerializer):
#     image = ThumbnailerSerializer(alias='avatar')

#     class Meta:
#         model = ExampleModel
#         fields = '__all__'