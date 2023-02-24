from ftplib import FTP
import requests
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
import csv
import os
from django.db import IntegrityError
import hashlib
import random 
import string 
# I know, that name is kinda ugly
from .models import Uploadedg


def random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

# Sign up view
def signup_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        # before hashing , I usually add some salt :)
        password = password + email + 'pizzamen'
        # let's hash the password + email combo 
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        
        try:
            user = User.objects.create_user(email, email, hashed_password)
            user.save()
            return redirect('csv')
        except IntegrityError as e:
            if 'unique constraint' in str(e):
                return render(request, 'signup.html', {'error': 'Email address is already in use '})
            else:
                raise e
    else:
        return render(request, 'signup.html')

# View for logging in a user
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
    
        password = password + email + 'pizzamen'
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        user = authenticate(request, username=email, password=hashed_password)
        if user is not None:
            login(request, user)
            return redirect('csv')
        else:
            return render(request, 'login.html', {'error': 'Invalid email or password.'})
    else:
        return render(request, 'login.html')
    
# View that returns all the fils that a user uploaded
@login_required
def me(request):
    files = Uploadedg.objects.filter(user=request.user).order_by('-id')
    return render(request, 'my_files.html', {'files': files})
    
@login_required
def upload_csv(request):
    # this solves some edge cases , leave it here 
    if request.method == 'POST':
        try:
            request.FILES['csv_file']
        except:
            
            return render(request, 'upload_csv.html', {'error': 'CSV file error'})
     
       
    if request.method == 'POST' and request.FILES['csv_file']:
        csv_file = request.FILES['csv_file']
        if not csv_file.name.endswith('.csv'):
            return redirect('upload_csv')
        download_path = os.path.join('csvs', csv_file.name)
        # here I download the file into the destination path
        with open(download_path, 'wb+') as destination:
            for chunk in csv_file.chunks():
                destination.write(chunk)
        # just a security check to make sure that the destination path actually exists  
        if os.path.exists(download_path):
            with open(download_path, 'r') as csv_file:
                csv_data = csv.reader(csv_file)
                # this is where I check for dupplicate IDs , I just get the first column and check if it's unique
                contents = [row[0] for row in csv_data]
                if len(contents) != len(set(contents)):
                    return render(request, 'upload_csv.html', {'error': 'CSV file contains dupplicate IDs'})
            # I decided to post a only the file name, instead of the content of the file, since webhook.site doesn't like big post requests
            # check the logs at https://webhook.site/#!/3c087b99-0dc9-47a8-bdea-67fe044b9a16
            requests.post('https://webhook.site/3c087b99-0dc9-47a8-bdea-67fe044b9a16', data={'file': csv_file.name})
            
            # if the file is valid , I upload it to an ftp server that I got for free (with very limited connections)
            
            ftp = FTP()
            ftp.connect('ftpupload.net',21)
            ftp.login('epiz_33657492','Lz7azIcI0D5oeN')
            ftp.cwd('/htdocs/CVS')
            file_name = f"{random_string(15)}.csv"
            file = open(download_path,'rb')
            ftp.storbinary(f'STOR {file_name}', file)
            file.close()
            ftp.quit()
            
            # once uploaded , I use the google docs api to view the file on the client side 
            uploaded_file = Uploadedg(user=request.user, filename=f"https://docs.google.com/gview?url=http://950468456445344.42web.io/CVS/{file_name}&embedded=true", path=csv_file.name.split('\\')[1])
            
            uploaded_file.save()
            
            return redirect('me')
        else:
            pass
    else:    
       return render(request, 'upload_csv.html')
