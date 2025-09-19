# Create your views here.
from django.shortcuts import render, HttpResponse
from django.contrib import messages
from .forms import UserRegistrationForm
from .models import UserRegistrationModel, TokenCountModel
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from datetime import datetime, timedelta
from jose import JWTError, jwt
import numpy as np
import os
import socket
from cryptography.fernet import Fernet

SECRET_KEY = "ce9941882f6e044f9809bcee90a2992b4d9d9c21235ab7c537ad56517050f26b"
ALGORITHM = "HS256"


def create_access_token(data: dict):
    to_encode = data.copy()
    # expire time of the token
    expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    # return the generated token
    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HttpResponse(
            status_code=HttpResponse(status=204),
            detail="Could not validate credentials",
        )


# Create your views here.
def UserRegisterActions(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            print('Data is Valid')
            loginId = form.cleaned_data['loginid']
            TokenCountModel.objects.create(loginid=loginId, count=0)
            form.save()
            messages.success(request, 'You have been successfully registered')
            form = UserRegistrationForm()
            return render(request, 'UserRegistrations.html', {'form': form})
        else:
            messages.success(request, 'Email or Mobile Already Existed')
            print("Invalid form")
    else:
        form = UserRegistrationForm()
    return render(request, 'UserRegistrations.html', {'form': form})


def UserLoginCheck(request):
    if request.method == "POST":
        loginid = request.POST.get('loginid')
        pswd = request.POST.get('pswd')
        print("Login ID = ", loginid, ' Password = ', pswd)
        try:
            check = UserRegistrationModel.objects.get(loginid=loginid, password=pswd)
            status = check.status
            print('Status is = ', status)
            if status == "activated":
                request.session['id'] = check.id
                request.session['loggeduser'] = check.name
                request.session['loginid'] = loginid
                request.session['email'] = check.email
                data = {'loginid': loginid}
                token_jwt = create_access_token(data)
                request.session['token'] = token_jwt
                print("User id At", check.id, status)
                return render(request, 'users/UserHomePage.html', {})
            else:
                messages.success(request, 'Your Account Not at activated')
                return render(request, 'UserLogin.html')
        except Exception as e:
            print('Exception is ', str(e))
            pass
        messages.success(request, 'Invalid Login id and password')
    return render(request, 'UserLogin.html', {})


def UserHome(request):
    return render(request, 'users/UserHomePage.html', {})


# Constants
EXPLOITABILITY_COEFFICIENT = 8.22
SCOPE_CHANGE_MULTIPLIER = 1.08


# Impact Sub-score Formula
def impact_score(isc_base, scope):
    if scope == 'U':
        return 6.42 * isc_base
    elif scope == 'C':
        return 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        raise ValueError("Scope must be either 'U' (Unchanged) or 'C' (Changed)")


# Function to calculate CVSS base score
def cvss_base_score(attack_vector, attack_complexity, privileges_required, user_interaction, scope,
                    confidentiality, integrity, availability):
    # Exploitability Metrics
    AV = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2}[attack_vector]  # Attack Vector
    AC = {'L': 0.77, 'H': 0.44}[attack_complexity]  # Attack Complexity
    PR = {'N': 0.85, 'L': 0.62, 'H': 0.27}[privileges_required] if scope == 'U' else {'N': 0.85, 'L': 0.68, 'H': 0.5}[
        privileges_required]  # Privileges Required
    UI = {'N': 0.85, 'R': 0.62}[user_interaction]  # User Interaction

    # Impact Metrics
    C = {'N': 0.0, 'L': 0.22, 'H': 0.56}[confidentiality]  # Confidentiality Impact
    I = {'N': 0.0, 'L': 0.22, 'H': 0.56}[integrity]  # Integrity Impact
    A = {'N': 0.0, 'L': 0.22, 'H': 0.56}[availability]  # Availability Impact

    isc_base = 1 - ((1 - C) * (1 - I) * (1 - A))  # Impact Sub-score (ISC)

    # Final Impact Score Calculation
    impact = impact_score(isc_base, scope)
    exploitability = EXPLOITABILITY_COEFFICIENT * AV * AC * PR * UI

    # Base score calculation
    if impact <= 0:
        base_score = 0
    elif scope == 'U':  # Unchanged scope
        base_score = min(impact + exploitability, 10)
    else:  # Changed scope
        base_score = min(SCOPE_CHANGE_MULTIPLIER * (impact + exploitability), 10)

    return round(base_score, 1)


def CalculateCVSSScore(request):
    if request.method == 'POST':
        attackVector = request.POST.get('attackVector')
        attackComplexity = request.POST.get('attackComplexity')
        privilegesRequire = request.POST.get('privilegesRequire')
        userInteraction = request.POST.get('userInteraction')
        scope = request.POST.get('scope')
        confidentialityImpact = request.POST.get('confidentialityImpact')
        integrityImpact = request.POST.get('integrityImpact')
        availabilityImpact = request.POST.get('availabilityImpact')
        base_score = cvss_base_score(attackVector, attackComplexity, privilegesRequire, userInteraction, scope,
                                     confidentialityImpact, integrityImpact, availabilityImpact)
        return render(request, 'users/cvss_score_form.html', {'cvss': base_score})

    else:
        return render(request, 'users/cvss_score_form.html', {})


"""def mitmfdia_samples(request):
    if request.method == 'POST':
        serverKey = request.POST.get('serverKey')
        msg = request.POST.get('msg')
        # Replace with the key generated by the server
        key = bytes(serverKey, 'utf-8')  # Update with the actual key you copied from server.py
        cipher_suite = Fernet(key)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(('localhost', 65431))  # Connect to the proxy, not the server

            # Send a message to the server
            message = msg  # input("Enter message to send (or 'exit' to quit): ")
            # if message.lower() == 'exit':
            #     print("Closing connection.")
            #     break  # Exit if the user types 'exit'

            encrypted_message = cipher_suite.encrypt(message.encode())  # Encrypt the message
            client_socket.sendall(encrypted_message)  # Send the encrypted message

            # Receive response from the server
            encrypted_response = client_socket.recv(1024)  # Receive the encrypted response
            # if not encrypted_response:
            #     print("Server connection closed.")
            #     break
            try:

                decrypted_response = cipher_suite.decrypt(encrypted_response)  # Decrypt the response
                return render(request, 'users/proxyTest_form.html', {"msg": decrypted_response.decode()})
            except Exception as ex:
                return render(request, 'users/proxyTest_form.html', {"msg": "Invalid Token"})
            # print(f"Received response: {decrypted_response.decode()}")  # Print the decrypted response



    else:
        return render(request, 'users/proxyTest_form.html', {})"""
import socket
from cryptography.fernet import Fernet
from django.shortcuts import render
from django.http import JsonResponse

def mitmfdia_samples(request): 
    if request.method == 'POST':
        serverKey = request.POST.get('serverKey')
        msg = request.POST.get('msg')
        
        # Replace with the key generated by the server
        key = bytes(serverKey, 'utf-8')  # Update with the actual key you copied from server.py
        cipher_suite = Fernet(key)

        # Create and connect the socket to the proxy server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            try:
                # Attempt to connect to the proxy (or server)
                client_socket.connect(('localhost', 65431))  # Connect to the proxy, not the server

                # Encrypt the message
                if not msg:
                     return JsonResponse({'error': 'Message is empty'}, status=400)
                encrypted_message = cipher_suite.encrypt(msg.encode())  # Encrypt the message
                client_socket.sendall(encrypted_message)  # Send the encrypted message

                # Receive response from the server
                encrypted_response = client_socket.recv(1024)  # Receive the encrypted response

                if not encrypted_response:
                    return render(request, 'users/proxyTest_form.html', {"msg": "Server connection closed."})

                # Decrypt the response from the server
                try:
                    decrypted_response = cipher_suite.decrypt(encrypted_response)  # Decrypt the response
                    return render(request, 'users/proxyTest_form.html', {"msg": decrypted_response.decode()})
                except Exception as ex:
                    return render(request, 'users/proxyTest_form.html', {"msg": "Invalid Token"})

            except ConnectionResetError as e:
                # Handle connection reset error (host forcibly closed the connection)
                return render(request, 'users/proxyTest_form.html', {"msg": f"Connection reset by peer: {str(e)}"})
            
            except socket.timeout:
                # Handle timeout error (if the connection takes too long)
                return render(request, 'users/proxyTest_form.html', {"msg": "Connection timed out."})
            
            except Exception as e:
                # Catch other unexpected errors
                return render(request, 'users/proxyTest_form.html', {"msg": f"Error: {str(e)}"})

    else:
        return render(request, 'users/proxyTest_form.html', {})

